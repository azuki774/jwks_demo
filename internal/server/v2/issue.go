package v2

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-jwt/jwt"
)

const tokenExpirationTime = 60 // トークンの有効期限 (秒)

func (s *Server) Issue(kid string) (jwtStr string, err error) {
	// PEMデータをデコード
	privateKeyLine := s.privateKeys[kid]
	if privateKeyLine == "" {
		slog.Warn("private key not found for the given kid", "kid", kid)
		return "", fmt.Errorf("private key not found")
	}

	block, rest := pem.Decode([]byte(privateKeyLine))
	if block == nil {
		slog.Error("failed to decode PEM block", "rest", string(rest))
		return "", fmt.Errorf("failed to decode PEM block")
	}
	if block.Type != "PRIVATE KEY" {
		slog.Error("unsupported key type", "type", block.Type)
		return "", fmt.Errorf("unsupported key type")
	}

	// PKCS#8 形式の秘密鍵をパース
	parsedKeyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		slog.Error("failed to parse PKCS#8 private key from PEM block", "error", err, "pem_block_bytes_length", len(block.Bytes))
		return "", err
	}

	// パースされた鍵が *ed25519.PrivateKey かどうかを型アサーションで確認
	privateKey, ok := parsedKeyInterface.(ed25519.PrivateKey)
	if !ok {
		// ed25519 以外の鍵の場合
		keyType := fmt.Sprintf("%T", parsedKeyInterface)
		slog.Error("parsed key is not an Ed25519 private key", "actual_type", keyType, "err", err)
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": "jwks_demo_issuer",
		"sub": "jwks_demo_subject",
		"exp": time.Now().Add(time.Second * 1 * tokenExpirationTime).Unix(),
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
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	slog.Info("successfully issued JWT", "kid", kid, "token", signedToken)
	return signedToken, nil
}
