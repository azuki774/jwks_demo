package issue

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
)

type Issuer struct {
	FileOperator FileOperator
}

type FileOperator interface {
	LoadTxtFile(filePath string) ([]byte, error)
}

func NewIssuer(f FileOperator) *Issuer {
	return &Issuer{
		FileOperator: f,
	}
}

func (i *Issuer) Issue(privateKeyPath string, kid string) error {
	privateKeyLine, err := i.FileOperator.LoadTxtFile(privateKeyPath)
	if err != nil {
		return err
	}

	// PEMデータをデコード
	block, rest := pem.Decode(privateKeyLine)
	if block == nil {
		slog.Error("failed to decode PEM block", "rest", string(rest))
		return err
	}
	if block.Type != "PRIVATE KEY" {
		slog.Error("unsupported key type", "type", block.Type)
		return err
	}

	// PKCS#8 形式の秘密鍵をパース
	parsedKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		slog.Error("failed to parse PKCS#8 private key from PEM block", "error", err, "pem_block_bytes_length", len(block.Bytes))
		return err
	}

	// パースされた鍵が *ed25519.PrivateKey かどうかを型アサーションで確認
	privateKey, ok := parsedKeyInterface.(ed25519.PrivateKey)
	if !ok {
		// ed25519 以外の鍵の場合
		keyType := fmt.Sprintf("%T", parsedKeyInterface)
		slog.Error("parsed key is not an Ed25519 private key", "actual_type", keyType, "err", err)
		return err
	}

	claims := jwt.MapClaims{
		"iss": "jwks_demo_issuer",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)

	// ヘッダーに Key ID (kid) を設定
	if kid != "" {
		token.Header["kid"] = kid
	} else {
		slog.Warn("kid is empty. 'kid' header will not be set")
	}

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		slog.Error("failed to sign token", "error", err)
		return fmt.Errorf("failed to sign token: %w", err)
	}

	slog.Info("successfully issued JWT", "kid", kid, "token", signedToken)
	return nil
}

// publicKeyLine, err := i.FileOperator.LoadTxtFile(publicKeyPath)
// if err != nil {
// 	return err
// }

// // ParseAuthorizedKey を使って公開鍵の行をパース
// // この関数は "ssh-ed25519 BASE64_KEY optional_comment" という形式を扱えます。
// // また、行頭のオプション (例: "command=\"...\" ssh-ed25519 ...") も処理できます。
// publicKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyLine))
// if err != nil {
// 	slog.Error("failed to parse public key", "error", err)
// 	return err
// }

// // パースされた鍵が Ed25519 かどうかを確認
// if publicKey.Type() != ssh.KeyAlgoED25519 {
// 	slog.Error("this is not an Ed25519 key")
// 	return fmt.Errorf("this is not an Ed25519 key")
// }

// openssl genpkey -algorithm ed25519 -out ed25519.pem
// openssl pkey -in ed25519.pem -pubout -out ed25519_pub.pem
