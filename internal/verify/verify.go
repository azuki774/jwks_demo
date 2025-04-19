package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jwks_demo/internal/model"
)

type MyCustomClaims struct {
	jwt.RegisteredClaims
}

type Verifier struct {
	trustedPublicKeys map[string]ed25519.PublicKey // 検証に使う公開鍵を保持するマップ (kid -> PublicKey)
	JWSTClient        JWSTClient
}

type JWSTClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewVerfier() *Verifier {
	return &Verifier{
		trustedPublicKeys: make(map[string]ed25519.PublicKey),
		JWSTClient:        &http.Client{},
	}
}

// テスト用初期化関数
func (v *Verifier) LoadKeys() error {
	if v.trustedPublicKeys == nil {
		v.trustedPublicKeys = make(map[string]ed25519.PublicKey)
	}

	url, _ := url.Parse("http://localhost:8080/.well-known/jwks.json")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    url,
		Header: http.Header{"Accept": []string{"application/json"}},
		Body:   nil,
	}

	res, err := v.JWSTClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		io.ReadAll(res.Body) // エラー内容は無視しても良い
		return fmt.Errorf("failed to fetch JWKS: status code %d", res.StatusCode)
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	// res.Body を JSON としてパースする
	var responseJWKS model.Response
	err = json.Unmarshal(resBody, &responseJWKS)
	if err != nil {
		return fmt.Errorf("failed to Unmarshal response body: %w", err)
	}

	loadedKeys := 0
	for _, key := range responseJWKS.Keys {
		// Ed25519 キーのみを処理 (必要に応じて他のタイプもサポート)
		if key.Kty == "OKP" && key.Crv == "Ed25519" && key.Use == "sig" && key.Kid != "" && key.X != "" {
			// x パラメータ (base64urlエンコードされた公開鍵) をデコード
			publicKeyBytes, err := base64.RawURLEncoding.DecodeString(key.X)
			if err != nil {
				slog.Warn("Failed to decode base64url public key 'x'", "kid", key.Kid, "error", err)
				continue // 次のキーへ
			}

			// バイト数が Ed25519 公開鍵として正しいか確認 (オプションだが推奨)
			if len(publicKeyBytes) != ed25519.PublicKeySize {
				slog.Warn("Decoded public key has incorrect size for Ed25519", "kid", key.Kid, "expected_size", ed25519.PublicKeySize, "actual_size", len(publicKeyBytes))
				continue // 次のキーへ
			}

			// デコードしたバイト列は ed25519.PublicKey 型として扱える
			v.trustedPublicKeys[key.Kid] = ed25519.PublicKey(publicKeyBytes)
			slog.Info("Successfully loaded Ed25519 public key from JWKS", "index", loadedKeys, "kid", key.Kid, "key_length", len(publicKeyBytes))
			loadedKeys++
		} else {
			slog.Info("Skipping key in JWKS", "kid", key.Kid, "kty", key.Kty, "crv", key.Crv, "use", key.Use)
		}
	}

	return nil
}

func (v *Verifier) Verify(jwtString string) (ok bool, err error) {
	if err := v.LoadKeys(); err != nil {
		slog.Error("failed to load keys", "error", err)
		return false, err
	}

	token, err := jwt.ParseWithClaims(jwtString, &MyCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// ヘッダーからkidを取得
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			slog.Warn("kid header missing or not a string")
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
