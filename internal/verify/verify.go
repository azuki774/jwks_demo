package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
}

type Verifier struct {
	trustedPublicKeys map[string]ed25519.PublicKey // 検証に使う公開鍵を保持するマップ (kid -> PublicKey)
}

// テスト用初期化関数
func (v *Verifier) LoadKeys() error {
	v.trustedPublicKeys = make(map[string]ed25519.PublicKey)
	// 固定の公開鍵 PEM データ
	const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PUBLIC KEY-----`
	const fixedKid = "key-001"
	slog.Info("Initializing with fixed public key for kid", "kid", fixedKid)

	// PEMデータをデコード
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode fixed PEM block containing public key")
	}
	if block.Type != "PUBLIC KEY" {
		slog.Warn(fmt.Sprintf("fixed PEM block type is not 'PUBLIC KEY', got '%s'. Attempting to parse anyway.", block.Type))
	}

	// PKIX形式の公開鍵をパース
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse PKIX public key from fixed PEM: %w", err)
	}

	// ed25519.PublicKey 型へアサーション
	edPubKey, ok := pub.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("fixed key is not an ed25519.PublicKey, type is %T", pub)
	}

	// マップに格納
	v.trustedPublicKeys[fixedKid] = edPubKey
	slog.Info(fmt.Sprintf("successfully initialized fixed ed25519.PublicKey for kid: %s (length: %d)", fixedKid, len(edPubKey)))

	if len(v.trustedPublicKeys) == 0 {
		slog.Warn("mo public keys loaded for verification. All verifications will fail.")
	}

	return nil
}

func (v *Verifier) verify(jwtString string) (ok bool, err error) {
	if err := v.LoadKeys(); err != nil {
		slog.Error("failed to load keys", "error", err)
		return false, err
	}

	token, err := jwt.ParseWithClaims(jwtString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// ヘッダーからkidを取得
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("kid header missing or not a string")
		}

		// アルゴリズムの検証
		if _, ok := token.Method.(*jwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// kidに対応する検証キーを取得
		publicKey, ok := v.trustedPublicKeys[kid]
		if !ok {
			return nil, fmt.Errorf("verification key not found for kid: %s", kid)
		}

		return publicKey, nil
	})
	if err != nil {
		return false, err
	}

	if claims, ok := token.Claims.(*MyCustomClaims); ok && token.Valid {
		slog.Info("token is valid", "claims", claims)
	} else {
		slog.Info("token is invalid", "claims", claims)
		return false, nil // エラーなしでNG
	}

	return true, nil
}
