# fastapi-verified-permissions

English · [日本語](https://github.com/yuu551/fastapi-verified-permissions/blob/main/README.ja.md) · [Hono version for TypeScript](https://github.com/yuu551/hono-verified-permissions)

Protect individual FastAPI routes with [Amazon Verified Permissions](https://aws.amazon.com/verified-permissions/). Declare an action and a resource dependency, then add the resulting dependency to a route with `Depends()`. Boto3 makes the authorization request in a synchronous FastAPI dependency, so an async route can use the same API.

## Install

Requires Python 3.11 or later. In a uv project, run

```sh
uv add fastapi-verified-permissions
```

To install with pip, run

```sh
python -m pip install fastapi-verified-permissions
```

[PyPI](https://pypi.org/project/fastapi-verified-permissions/) · [GitHub Releases](https://github.com/yuu551/fastapi-verified-permissions/releases)

## Protect a document endpoint

Register the Cognito user pool or OIDC provider as an identity source for your policy store. Set `POLICY_STORE_ID`, configure the AWS region and credentials for Boto3, and grant the application role `verifiedpermissions:IsAuthorizedWithToken` on the store.

```python
import os

from fastapi import Depends, FastAPI
from fastapi_verified_permissions import Authorization, Entity, VerifiedPermissions

app = FastAPI()
avp = VerifiedPermissions(os.environ["POLICY_STORE_ID"])

def document(document_id: str) -> Entity:
    return Entity("Demo::Document", document_id)

can_read = avp.require(
    action=Entity("Demo::Action", "view"),
    resource=document,
    token="accessToken",
)

@app.get("/documents/{document_id}")
async def read_document(document_id: str, permit: Authorization = Depends(can_read)):
    return {"document": document_id, "reader": permit.principal.id}
```

The client sends `Authorization: Bearer <token>`. Verified Permissions checks the token and returns the principal. To use ID tokens, set `token="identityToken"`. A Cedar policy for a Cognito user can refer to the user pool ID and the user's `sub`:

```cedar
permit(
    principal == Demo::User::"<user-pool-id>|<sub>",
    action == Demo::Action::"view",
    resource == Demo::Document::"guide"
);
```

With the policy in place, set `API_URL` to the application URL and `ACCESS_TOKEN` to a Cognito access token. Then request the document.

```sh
curl -i -H "Authorization: Bearer ${ACCESS_TOKEN}" "${API_URL}/documents/guide"
```

With only this policy in the store, the named user receives `200` and the document ID. A valid token from a different user yields `403` for the same document.

If the application already authenticates the caller, pass `principal=current_user` instead of a token mode. The dependency must return an `Entity` from the verified session or `None` for an anonymous request. This mode calls `IsAuthorized` and requires `verifiedpermissions:IsAuthorized`. The optional `context` and `entities` dependencies return a Cedar JSON object and an array of Cedar entities. FastAPI resolves synchronous and asynchronous dependencies in all modes.

| Result | Route behavior |
| --- | --- |
| Allowed | Handler receives `Authorization(principal, determining_policies)`. |
| Missing principal or malformed bearer header | Returns 401. |
| Explicit or default deny | Returns 403. |
| AWS SDK or service error, including a service-rejected token, or missing decision | Returns 503. |

Errors raised by application dependencies follow FastAPI's normal exception handling. An existing Boto3 client can be passed as `VerifiedPermissions(store_id, client=client)`.

## AWS reference architecture

![The client signs in with Cognito. API Gateway verifies the JWT and invokes FastAPI on Lambda. FastAPI asks Verified Permissions whether the user can read the document.](https://raw.githubusercontent.com/yuu551/fastapi-verified-permissions/v0.1.1/docs/aws-architecture.png)

API Gateway verifies the Cognito JWT before invoking Lambda. The FastAPI dependency maps the document ID in the request path to a Cedar resource and asks Verified Permissions whether the caller can read it. [Editable diagram](https://github.com/yuu551/fastapi-verified-permissions/blob/v0.1.1/docs/aws-architecture.drawio)

In a live deployment in `us-east-1`, 14 HTTPS checks covered all three identity modes. Alice could read `guide`. Requests for `draft` from Alice and for `guide` from Bob returned 403 in every mode. An explicit Cedar forbid blocked Alice in every mode, and the gateway rejected an anonymous request.

## Development

```sh
uv sync --locked
uv run pytest
uv build
```

With [AWS Emulator](https://docs.aws.amazon.com/emulator/latest/userguide/getting-started.html) running, execute the integration test separately:

```sh
uv run pytest integration/test_emulator.py
```

It connects to `https://127.0.0.1:9297` using the emulator's credentials and CA. Set `AWS_EMULATOR_PORT` for another port. The test creates a policy store and a Cognito user pool, signs two users in, and checks entity, access-token and ID-token requests. It verifies document-level access and explicit forbids, then deletes the test resources.

[Route example](https://github.com/yuu551/fastapi-verified-permissions/blob/v0.1.1/examples/documents.py) · [Apache License 2.0](https://github.com/yuu551/fastapi-verified-permissions/blob/v0.1.1/LICENSE)
