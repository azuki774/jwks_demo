package v2

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
)

// PEM public key -> public key
func parsePemPublicKeyLine(pemLine string) (ed25519.PublicKey, error) {
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

	pubKeyBytes, ok := genericPublicKey.(ed25519.PublicKey)
	if !ok {
		slog.Info(fmt.Sprintf("parsed key is not an Ed25519 public key. Actual type: %T", genericPublicKey))
	}

	slog.Info("Successfully extracted raw Ed25519 public key bytes", "len", len(pubKeyBytes))

	return pubKeyBytes, nil
}
