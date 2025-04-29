# jwks_demo
JWKS demo programing

- クライアントと Issuer の間の認証は省略しています
- Issuer が `files/private` 内の秘密鍵、 JWKS が `files/public` 内の公開鍵を利用します。
    - kid = ファイル名の拡張子なし部分


## I/F (server/v2)
テスト用のプログラム（ダミーサービス）と、Issuer、JWKS を提供する。
この方法で起動する場合は、`files` 配下のファイルは利用しない。

### Issuer

- POST `http://localhost:8080/issue/secret/{kid}`
    - (Issuer) 管理用エンドポイント
    - 新しいシークレットを生成する

- POST `http://localhost:8080/issue/token`
    - (Issuer) 新しいJWT認証を要求する
    - クライアント <-> Issuer 間の認証実装は省略

- GET `http://localhost:8080/.well-known/jwks.json`
    - (JWKS) JWKSとして、有効な公開鍵を示す

- GET `http://localhost:3000/service`
    - （サービス）ダミーサービス用のエンドポイント
    - JWKS を利用した JWT 認証を行い、問題なければ 200、問題があれば 401 を返す。
