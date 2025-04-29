package issue

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
)

func GeneratePrivateKey() (privateKeyPEMStr string, publicKeyPEMStr string, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		slog.Error("failed to create key pair", "err", err)
		return "", "", err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		slog.Error("failed to marshal", "err", err)
		return "", "", err
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("failed to marshal", "err", err)
		return "", "", err
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	privateKeyPEMStr = string(privateKeyPEM)
	publicKeyPEMStr = string(publicKeyPEM)

	return privateKeyPEMStr, publicKeyPEMStr, nil
}
