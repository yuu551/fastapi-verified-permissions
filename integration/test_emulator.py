"""Run explicitly with pytest integration/test_emulator.py against AWS Emulator."""

from configparser import ConfigParser
from contextlib import ExitStack
from pathlib import Path
import os
from uuid import uuid4

import boto3
from botocore.config import Config
from fastapi import Depends, FastAPI, Request
from fastapi.testclient import TestClient

from fastapi_verified_permissions import Authorization, Entity, VerifiedPermissions


def local_session():
    port = int(os.environ.get("AWS_EMULATOR_PORT", "9297"))
    if not 0 < port < 65536:
        raise ValueError("AWS_EMULATOR_PORT must be between 1 and 65535")
    root = Path.home() / ".aws" / "emulator" / str(port)
    credentials = ConfigParser(interpolation=None)
    with (root / "emulator_credentials").open() as stream:
        credentials.read_file(stream)
    cert = root / "ca.pem"
    assert cert.is_file(), f"Missing AWS Emulator CA: {cert}"
    profile = credentials["default"]
    session = boto3.Session(
        aws_access_key_id=profile["aws_access_key_id"],
        aws_secret_access_key=profile["aws_secret_access_key"],
        aws_session_token=profile.get("aws_session_token"),
        region_name="us-west-2",
    )
    return session, {
        "endpoint_url": f"https://127.0.0.1:{port}",
        "verify": str(cert),
        "config": Config(proxies={}, retries={"total_max_attempts": 1}),
    }


def sign_in(idp, pool, app_client, username):
    password = "Aa1!" + uuid4().hex
    user = idp.admin_create_user(
        UserPoolId=pool, Username=username, MessageAction="SUPPRESS"
    )["User"]
    sub = next(a["Value"] for a in user["Attributes"] if a["Name"] == "sub")
    idp.admin_set_user_password(
        UserPoolId=pool, Username=username, Password=password, Permanent=True
    )
    tokens = idp.initiate_auth(
        ClientId=app_client,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    return Entity("Demo::User", f"{pool}|{sub}"), tokens


def test_document_authorization_on_aws_emulator():
    session, options = local_session()
    with ExitStack() as cleanup:
        avp = session.client("verifiedpermissions", **options)
        cleanup.callback(avp.close)
        idp = session.client("cognito-idp", **options)
        cleanup.callback(idp.close)
        store = avp.create_policy_store(validationSettings={"mode": "OFF"})[
            "policyStoreId"
        ]
        cleanup.callback(avp.delete_policy_store, policyStoreId=store)
        pool = idp.create_user_pool(PoolName=f"fastapi-{uuid4()}")["UserPool"]
        cleanup.callback(idp.delete_user_pool, UserPoolId=pool["Id"])
        app_client = idp.create_user_pool_client(
            UserPoolId=pool["Id"],
            ClientName="documents",
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )["UserPoolClient"]["ClientId"]
        avp.create_identity_source(
            policyStoreId=store,
            principalEntityType="Demo::User",
            configuration={
                "cognitoUserPoolConfiguration": {
                    "userPoolArn": pool["Arn"],
                    "clientIds": [app_client],
                }
            },
        )
        alice, alice_tokens = sign_in(idp, pool["Id"], app_client, "alice")
        bob, bob_tokens = sign_in(idp, pool["Id"], app_client, "bob")

        auth = VerifiedPermissions(store, client=avp)
        app = FastAPI()
        sessions = {uuid4().hex: alice, uuid4().hex: bob}
        alice_session, bob_session = sessions

        def user(request: Request):
            return sessions.get(request.cookies.get("session"))

        def document(document_id: str):
            return Entity("Demo::Document", document_id)

        def add_route(mode, **identity):
            read = auth.require(
                action=Entity("Demo::Action", "view"), resource=document, **identity
            )

            @app.get(f"/{mode}/documents/{{document_id}}")
            def get_document(result: Authorization = Depends(read)):
                return {"reader": result.principal.id}

        add_route("entity", principal=user)
        add_route("access", token="accessToken")
        add_route("id", token="identityToken")
        http = cleanup.enter_context(TestClient(app))

        def policy(statement):
            avp.create_policy(
                policyStoreId=store, definition={"static": {"statement": statement}}
            )

        assert http.get("/access/documents/guide").status_code == 401
        entity_headers = {"Cookie": "session=" + alice_session}
        assert (
            http.get("/entity/documents/guide", headers=entity_headers).status_code
            == 403
        )
        policy(
            f'permit(principal == Demo::User::"{alice.id}", action == Demo::Action::"view", resource == Demo::Document::"guide");'
        )
        requests = [
            ("entity", entity_headers, {"Cookie": "session=" + bob_session}),
            (
                "access",
                {"Authorization": "Bearer " + alice_tokens["AccessToken"]},
                {"Authorization": "Bearer " + bob_tokens["AccessToken"]},
            ),
            (
                "id",
                {"Authorization": "Bearer " + alice_tokens["IdToken"]},
                {"Authorization": "Bearer " + bob_tokens["IdToken"]},
            ),
        ]
        for mode, allowed, denied in requests:
            path = f"/{mode}/documents/"
            response = http.get(path + "guide", headers=allowed)
            assert response.status_code == 200 and response.json() == {
                "reader": alice.id
            }
            assert http.get(path + "draft", headers=allowed).status_code == 403
            assert http.get(path + "guide", headers=denied).status_code == 403
        policy("forbid(principal, action, resource);")
        for mode, allowed, _ in requests:
            assert (
                http.get(f"/{mode}/documents/guide", headers=allowed).status_code == 403
            )
