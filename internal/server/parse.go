package server

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
)

// PEM public key -> public key
func parsePemPublicKeyLine(pemLine string) (ed25519.PublicKey, error) {
	// 1. PEMブロックをデコードする
	// pem.Decode は入力から最初のPEMブロックを見つけてデコードします
	block, rest := pem.Decode([]byte(pemLine))
	if block == nil {
		slog.Error(fmt.Sprintf("failed to decode PEM block containing public key. Remaining data: %s", string(rest)))
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	if block.Type != "PUBLIC KEY" {
		slog.Info(fmt.Sprintf("unexpected PEM block type: %q (expected \"PUBLIC KEY\")", block.Type))
		return nil, fmt.Errorf("unexpected PEM block type: %q (expected \"PUBLIC KEY\")", block.Type)
	}

	genericPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		slog.Error(fmt.Sprintf("failed to parse DER encoded public key: %v", err))
		return nil, err
	}

	// 4. パースされた公開鍵が期待する型 (ed25519.PublicKey) かどうかを確認します（型アサーション）
	//    Goの crypto/ed25519 パッケージでは、PublicKey型は []byte のエイリアス (type PublicKey []byte) です。
	pubKeyBytes, ok := genericPublicKey.(ed25519.PublicKey)
	if !ok {
		slog.Info(fmt.Sprintf("parsed key is not an Ed25519 public key. Actual type: %T", genericPublicKey))
	}

	// 5. 型アサーションが成功すれば、pubKeyBytes は生のEd25519公開鍵バイト列 (32バイト) です。
	slog.Info("Successfully extracted raw Ed25519 public key bytes", "len", len(pubKeyBytes))

	// xValue := base64.RawURLEncoding.EncodeToString(pubKeyBytes)
	return pubKeyBytes, nil
}
