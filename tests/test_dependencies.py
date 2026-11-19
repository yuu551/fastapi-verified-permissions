import json
from unittest.mock import Mock

import pytest
from botocore.exceptions import EndpointConnectionError
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from fastapi_verified_permissions import Authorization, Entity, VerifiedPermissions

ACTION = Entity("Demo::Action", "view")
ALICE = Entity("Demo::User", "alice")
ALLOW = {"decision": "ALLOW", "determiningPolicies": [{"policyId": "policy-1"}]}
PRINCIPAL = {"entityType": ALICE.type, "entityId": ALICE.id}


def application(client, **options):
    app = FastAPI()
    reached = []
    auth = VerifiedPermissions("test-store", client=client)

    async def resource(document_id: str):
        return Entity("Demo::Document", document_id)

    read = auth.require(action=ACTION, resource=resource, **options)

    @app.get("/documents/{document_id}")
    def get_document(result: Authorization = Depends(read)):
        reached.append(result)
        return {"reader": result.principal.id, "policies": result.determining_policies}

    return TestClient(app), reached


def test_entity_route_resolves_async_dependencies_and_sends_cedar_json():
    client = Mock()
    client.is_authorized.return_value = ALLOW
    entity = {"uid": {"type": "Demo::User", "id": "alice"}, "attrs": {}, "parents": []}

    async def principal():
        return ALICE

    app, reached = application(
        client,
        principal=principal,
        context=lambda: {"channel": "web"},
        entities=lambda: [entity],
    )
    response = app.get("/documents/guide")
    assert response.status_code == 200
    assert response.json() == {"reader": "alice", "policies": ["policy-1"]}
    assert reached == [Authorization(ALICE, ("policy-1",))]
    params = client.is_authorized.call_args.kwargs
    assert params["action"] == {"actionType": ACTION.type, "actionId": ACTION.id}
    assert params["resource"] == {"entityType": "Demo::Document", "entityId": "guide"}
    assert params["policyStoreId"] == "test-store" and params["principal"] == PRINCIPAL
    assert json.loads(params["context"]["cedarJson"]) == {"channel": "web"}
    assert json.loads(params["entities"]["cedarJson"]) == [entity]


@pytest.mark.parametrize("mode", ["accessToken", "identityToken"])
def test_token_route_uses_the_service_principal_and_openapi_bearer_scheme(mode):
    client = Mock()
    client.is_authorized_with_token.return_value = {**ALLOW, "principal": PRINCIPAL}
    app, _ = application(client, token=mode)
    response = app.get("/documents/guide", headers={"Authorization": "Bearer a.b.c"})
    assert response.status_code == 200 and response.json()["reader"] == "alice"
    params = client.is_authorized_with_token.call_args.kwargs
    assert params[mode] == "a.b.c" and "principal" not in params
    assert params["context"] == {"cedarJson": "{}"} and params["entities"] == {
        "cedarJson": "[]"
    }
    assert {"HTTPBearer": []} in app.get("/openapi.json").json()["paths"][
        "/documents/{document_id}"
    ]["get"]["security"]


@pytest.mark.parametrize(
    "headers",
    [
        [],
        [("Authorization", "Basic abc")],
        [("Authorization", "Bearer")],
        [("Authorization", "Bearer two tokens")],
        [("Authorization", "Bearer a"), ("Authorization", "Bearer b")],
    ],
)
def test_missing_or_malformed_token_rejects_before_avp(headers):
    client = Mock()
    app, reached = application(client, token="accessToken")
    response = app.get("/documents/guide", headers=headers)
    assert (
        response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"
    )
    assert not reached and not client.mock_calls


def test_missing_authenticated_principal_rejects_before_avp():
    client = Mock()
    app, reached = application(client, principal=lambda: None)
    assert app.get("/documents/guide").status_code == 401
    assert not reached and not client.mock_calls


@pytest.mark.parametrize(
    ("result", "status"), [({"decision": "DENY"}, 403), ({}, 503), (ALLOW, 503)]
)
def test_failed_decisions_do_not_reach_the_handler(result, status):
    client = Mock()
    client.is_authorized_with_token.return_value = result
    app, reached = application(client, token="identityToken")
    assert (
        app.get(
            "/documents/guide", headers={"Authorization": "Bearer x.y.z"}
        ).status_code
        == status
    )
    assert not reached


def test_service_failure_returns_generic_error():
    client = Mock()
    client.is_authorized.side_effect = EndpointConnectionError(endpoint_url="private")
    app, reached = application(client, principal=lambda: ALICE)
    resp = app.get("/documents/guide")
    assert resp.status_code == 503 and resp.json() == {
        "detail": "Authorization unavailable"
    }
    assert not reached


@pytest.mark.parametrize(
    "options",
    [{}, {"principal": lambda: ALICE, "token": "accessToken"}, {"token": "bad"}],
)
def test_route_requires_an_unambiguous_identity_mode(options):
    with pytest.raises(ValueError):
        application(Mock(), **options)
