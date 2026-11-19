import json
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, Protocol, TypeVar

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


@dataclass(frozen=True)
class Entity:
    type: str
    id: str


@dataclass(frozen=True)
class Authorization:
    principal: Entity
    determining_policies: tuple[str, ...]


class _Client(Protocol):
    def is_authorized(self, **params: Any) -> dict[str, Any]: ...
    def is_authorized_with_token(self, **params: Any) -> dict[str, Any]: ...


T = TypeVar("T")
Resolver = Callable[..., T | Awaitable[T]]
TokenType = Literal["accessToken", "identityToken"]
_bearer = HTTPBearer(auto_error=False)
_bearer_value = re.compile(r"[A-Za-z0-9._~+/-]+=*")


def _token(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
) -> str:
    if (
        len(request.headers.getlist("authorization")) != 1
        or credentials is None
        or not _bearer_value.fullmatch(credentials.credentials)
    ):
        raise HTTPException(401, "Unauthorized", headers={"WWW-Authenticate": "Bearer"})
    return credentials.credentials


def _empty_context() -> dict:
    return {}


def _empty_entities() -> list:
    return []


class VerifiedPermissions:
    def __init__(self, policy_store_id: str, *, client: _Client | None = None):
        if not policy_store_id:
            raise ValueError("policy_store_id is required")
        self._store = policy_store_id
        self._client = boto3.client("verifiedpermissions") if client is None else client

    def require(
        self,
        *,
        action: Entity,
        resource: Resolver[Entity],
        principal: Resolver[Entity | None] | None = None,
        token: TokenType | None = None,
        context: Resolver[Mapping[str, Any]] = _empty_context,
        entities: Resolver[Sequence[Mapping[str, Any]]] = _empty_entities,
    ) -> Callable[..., Authorization]:
        """Create a route dependency using a verified principal or a Cognito/OIDC token."""
        if (principal is None) == (token is None):
            raise ValueError("Specify exactly one of principal and token")
        if token is not None and token not in ("accessToken", "identityToken"):
            raise ValueError("token must be accessToken or identityToken")

        def authorize(
            identity: Entity | str | None = Depends(
                principal if principal is not None else _token
            ),
            target: Entity = Depends(resource),
            request_context: Mapping[str, Any] = Depends(context),
            request_entities: Sequence[Mapping[str, Any]] = Depends(entities),
        ) -> Authorization:
            if identity is None:
                raise HTTPException(401, "Unauthorized")

            params = {
                "policyStoreId": self._store,
                "action": {"actionType": action.type, "actionId": action.id},
                "resource": {"entityType": target.type, "entityId": target.id},
                "context": {
                    "cedarJson": json.dumps(dict(request_context), allow_nan=False)
                },
                "entities": {
                    "cedarJson": json.dumps(list(request_entities), allow_nan=False)
                },
            }
            if token is None:
                if not isinstance(identity, Entity):
                    raise TypeError("principal must return an Entity or None")
                params["principal"] = {
                    "entityType": identity.type,
                    "entityId": identity.id,
                }
                operation = self._client.is_authorized
            else:
                params[token] = identity
                operation = self._client.is_authorized_with_token

            try:
                result = operation(**params)
            except (BotoCoreError, ClientError):
                raise HTTPException(503, "Authorization unavailable") from None

            decision = result.get("decision")
            if decision == "DENY":
                raise HTTPException(403, "Forbidden")
            if decision != "ALLOW":
                raise HTTPException(503, "Authorization unavailable")

            if isinstance(identity, Entity):
                authorized_principal = identity
            else:
                resolved = result.get("principal") or {}
                if not resolved.get("entityType") or not resolved.get("entityId"):
                    raise HTTPException(503, "Authorization unavailable")
                authorized_principal = Entity(
                    resolved["entityType"], resolved["entityId"]
                )
            policies = tuple(
                p["policyId"]
                for p in result.get("determiningPolicies", [])
                if p.get("policyId")
            )
            return Authorization(authorized_principal, policies)

        return authorize
