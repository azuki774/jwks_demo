package verify

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"log/slog"

	"github.com/golang-jwt/jwt/v5"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
}

type Verifier struct {
}

// 検証に使う公開鍵を保持するマップ (kid -> PublicKey)
var trustedPublicKeys = make(map[string]ed25519.PublicKey)

// テスト用初期化関数
func initializeKeys() error {
	// 固定の公開鍵 PEM データ
	const publicKeyPEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ/gYirMuxyY=
-----END PUBLIC KEY-----`

	const fixedKid = "key-001"

	log.Printf("Initializing with fixed public key for kid: %s", fixedKid)

	// PEMデータをデコード
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode fixed PEM block containing public key")
	}
	if block.Type != "PUBLIC KEY" {
		// 厳密にはエラーにするか、警告にとどめるか
		log.Printf("Warning: Fixed PEM block type is not 'PUBLIC KEY', got '%s'. Attempting to parse anyway.", block.Type)
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
	trustedPublicKeys[fixedKid] = edPubKey
	log.Printf("Successfully initialized fixed ed25519.PublicKey for kid: %s (length: %d)", fixedKid, len(edPubKey))

	if len(trustedPublicKeys) == 0 {
		log.Println("Warning: No public keys loaded for verification. All verifications will fail.")
	}
	return nil
}

func (v *Verifier) verify(jwtString string) (ok bool, err error) {
	initializeKeys() // テスト用

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
		publicKey, ok := trustedPublicKeys[kid]
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
	}

	return true, nil
}
