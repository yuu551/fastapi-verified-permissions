from typing import Literal

from fastapi import Depends, FastAPI

from fastapi_verified_permissions import Authorization, Entity, VerifiedPermissions


def document(document_id: str) -> Entity:
    return Entity("Demo::Document", document_id)


def create_app(
    authorizer: VerifiedPermissions,
    mode: Literal["accessToken", "identityToken"] = "accessToken",
) -> FastAPI:
    app = FastAPI()
    read = authorizer.require(
        action=Entity("Demo::Action", "view"), resource=document, token=mode
    )

    @app.get("/documents/{document_id}")
    def read_document(document_id: str, decision: Authorization = Depends(read)):
        return {"document": document_id, "reader": decision.principal.id}

    return app
