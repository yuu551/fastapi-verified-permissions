# fastapi-verified-permissions

[English](./README.md) · 日本語

FastAPI のルートに Amazon Verified Permissions の認可を追加する Python パッケージです。アクションとリソースを指定し、ルートに `Depends()` で認可を組み込みます。Boto3 の呼び出しは FastAPI の同期依存関数で実行するため、`async def` のルートでも利用できます。

## インストール

Python 3.11 以降に対応しています。uv を使う場合は、プロジェクトのディレクトリで次のコマンドを実行します。

```sh
uv add "fastapi-verified-permissions @ git+https://github.com/yuu551/fastapi-verified-permissions.git@v0.1.0"
```

pip を使う場合はこちらです。

```sh
pip install "fastapi-verified-permissions @ git+https://github.com/yuu551/fastapi-verified-permissions.git@v0.1.0"
```

PyPI での初回公開後は、`uv add fastapi-verified-permissions` または `pip install fastapi-verified-permissions` でインストールできます。

## 文書の閲覧を制御する

ポリシーストアに Cognito ユーザープールまたは OIDC プロバイダーを ID ソースとして登録します。環境変数 `POLICY_STORE_ID` にストア ID を設定し、Boto3 のリージョンと認証情報を用意してください。実行ロールには対象ストアの `verifiedpermissions:IsAuthorizedWithToken` 権限が必要です。

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

クライアントは `Authorization: Bearer <token>` でトークンを送ります。Verified Permissions がトークンを検証して principal を特定します。ID トークンの場合は `token="identityToken"` を指定します。次の Cedar ポリシーは、指定した Cognito ユーザーにだけ `guide` の閲覧を許可します。

```cedar
permit(
    principal == Demo::User::"<user-pool-id>|<sub>",
    action == Demo::Action::"view",
    resource == Demo::Document::"guide"
);
```

アプリケーション側でセッションを検証している場合は `principal=current_user` を指定します。依存関数は、認証済みセッションから作った `Entity` を返します。未認証なら `None` を返してください。この方式では `IsAuthorized` を呼ぶため、実行ロールに `verifiedpermissions:IsAuthorized` が必要です。認可判定に追加の情報が必要なら、`context` で Cedar JSON のオブジェクトを、`entities` でエンティティの配列を返す依存関数を指定してください。依存関数は同期・非同期のどちらでも書けます。

| 判定 | FastAPI の動作 |
| --- | --- |
| 許可 | ハンドラーが `Authorization(principal, determining_policies)` を受け取る |
| principal がない、または Bearer ヘッダーが不正 | 401 を返す |
| 明示的な拒否、または許可ポリシーに一致しない | 403 を返す |
| トークンの検証エラーを含む AWS サービスエラー、SDK のエラー、判定の欠落 | 503 を返す |

アプリケーションの依存関数が投げた例外は FastAPI が通常どおり処理します。既存の Boto3 クライアントを使う場合は `VerifiedPermissions(store_id, client=client)` と指定します。

## AWS の構成例

![Cognito が発行したトークンを API Gateway が検証し、Lambda 上の FastAPI が Verified Permissions に認可を問い合わせる構成](./docs/aws-architecture.png)

クライアントは Cognito でサインインし、発行された JWT を API Gateway に送ります。API Gateway が JWT を検証して Lambda を呼び出すと、FastAPI はリクエストされた文書をそのユーザーが読めるかどうかを Verified Permissions に問い合わせます。[編集用の構成図](./docs/aws-architecture.drawio)

この構成を `us-east-1` にデプロイし、HTTPS 経由で14件の判定を確認しました。3方式とも Alice は `guide` を読めましたが、`draft` は拒否され、Bob は `guide` を読めませんでした。Cedar の `forbid` を追加すると Alice の閲覧も拒否されました。トークンを付けずに送ったリクエストには API Gateway が `401` を返しました。

## 開発とテスト

```sh
uv sync --locked
uv run pytest
uv build
```

[AWS Emulator](https://docs.aws.amazon.com/emulator/latest/userguide/getting-started.html) を起動してから、統合テストを実行します。

```sh
uv run pytest integration/test_emulator.py
```

テストの接続先は `https://127.0.0.1:9297` です。別ポートは `AWS_EMULATOR_PORT` で指定します。Emulator が発行した認証情報と CA を使い、テスト用のポリシーストアと Cognito ユーザープールを作成します。2人のユーザーでサインインし、エンティティ、アクセストークン、ID トークンの3方式で文書ごとの許可・拒否と `forbid` の動作を確認してから、リソースを削除します。

[ルートの実装例](./examples/documents.py) · [Hono 版](https://github.com/yuu551/hono-verified-permissions) · [Apache License 2.0](./LICENSE)
