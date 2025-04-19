package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/jwks_demo/internal/model"
)

func TestVerifier_verify(t *testing.T) {
	validKeyBytes, _ := base64.RawURLEncoding.DecodeString("wYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ_gYirMuxyY")
	validKid := "key-001"

	jwksResponse := model.Response{
		Keys: []model.Key{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: validKid,
				Use: "sig",
				Alg: "EdDSA",
				X:   base64.RawURLEncoding.EncodeToString(validKeyBytes),
			},
			{ // Add another key to test filtering/multiple keys
				Kty: "RSA", // Different type, should be skipped
				Kid: "rsa-key",
				Use: "sig",
				X:   "hogehoge",
			},
			{ // Add an invalid Ed25519 key
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "invalid-key",
				Use: "sig",
				X:   "invalid-base64!", // Invalid base64
			},
			{ // Add an Ed25519 key with wrong size
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "wrong-size-key",
				Use: "sig",
				X:   base64.RawURLEncoding.EncodeToString([]byte("short")), // Wrong size
			},
		},
	}
	jwksJsonBody, _ := json.Marshal(jwksResponse)

	type args struct {
		jwtString string
	}
	tests := []struct {
		name       string
		v          *Verifier
		mockClient JWSTClient
		args       args
		wantOk     bool
		wantErr    bool
	}{
		{
			name: "valid token",
			v:    &Verifier{},
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, string(jwksJsonBody)),
				Err:      nil,
			},
			args:    args{jwtString: "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJqd2tzX2RlbW9faXNzdWVyIn0.9oN0XeGWUBEiC2XmbwbMUCbN3J3rL3vlUENb8rj-OdZ1dfx7mGDZzH2FgXgDnWYgvmLg0d10kkSBzhjaJ-kCBQ"},
			wantOk:  true,
			wantErr: false,
		},
		{
			name: "invalid token 1",
			v:    &Verifier{},
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, string(jwksJsonBody)),
				Err:      nil,
			},
			args:    args{jwtString: "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1Qifa.eyJpc3MiOiJqd2tzX2RlbW9faXNzdWVyIn0.9oN0XeGWUBEiC2XmbwbMUCbN3J3rL3vlUENb8rj-OdZ1dfx7mGDZzH2FgXgDnWYgvmLg0d10kkSBzhjaJ-kCBQ"},
			wantOk:  false,
			wantErr: true,
		},
		{
			name: "invalid token 2",
			v:    &Verifier{},
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, string(jwksJsonBody)),
				Err:      nil,
			},
			args:    args{jwtString: "invalid"},
			wantOk:  false,
			wantErr: true,
		},
		{
			name: "http client error",
			v:    &Verifier{},
			mockClient: &MockJWSTClient{
				Response: nil,
				Err:      errors.New("network timeout"),
			},
			args:    args{jwtString: "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1Qifa.eyJpc3MiOiJqd2tzX2RlbW9faXNzdWVyIn0.9oN0XeGWUBEiC2XmbwbMUCbN3J3rL3vlUENb8rj-OdZ1dfx7mGDZzH2FgXgDnWYgvmLg0d10kkSBzhjaJ-kCBQ"},
			wantOk:  false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Verifier{
				JWSTClient: tt.mockClient,
			}
			gotOk, err := v.Verify(tt.args.jwtString)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("Verifier.Verify() = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func TestVerifier_LoadKeys(t *testing.T) {
	validKeyBytes, _ := base64.RawURLEncoding.DecodeString("wYDYgYnwhxMfR9hE7isN1rWHubXvEW1EJ_gYirMuxyY")
	validPublicKey := ed25519.PublicKey(validKeyBytes)
	validKid := "key-001"

	jwksResponse := model.Response{
		Keys: []model.Key{
			{
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: validKid,
				Use: "sig",
				Alg: "EdDSA",
				X:   base64.RawURLEncoding.EncodeToString(validKeyBytes),
			},
			{ // Add another key to test filtering/multiple keys
				Kty: "RSA", // Different type, should be skipped
				Kid: "rsa-key",
				Use: "sig",
				X:   "hogehoge",
			},
			{ // Add an invalid Ed25519 key
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "invalid-key",
				Use: "sig",
				X:   "invalid-base64!", // Invalid base64
			},
			{ // Add an Ed25519 key with wrong size
				Kty: "OKP",
				Crv: "Ed25519",
				Kid: "wrong-size-key",
				Use: "sig",
				X:   base64.RawURLEncoding.EncodeToString([]byte("short")), // Wrong size
			},
		},
	}
	jwksJsonBody, _ := json.Marshal(jwksResponse)

	tests := []struct {
		name               string
		mockClient         JWSTClient
		initialKeys        map[string]ed25519.PublicKey // Test initializing with existing keys
		wantTrustedKeys    map[string]ed25519.PublicKey
		wantErr            bool
		wantErrMsgContains string
	}{
		{
			name: "successful load",
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, string(jwksJsonBody)),
				Err:      nil,
			},
			initialKeys: nil, // Start fresh
			wantTrustedKeys: map[string]ed25519.PublicKey{
				validKid: validPublicKey,
			},
			wantErr: false,
		},
		{
			name: "http client error",
			mockClient: &MockJWSTClient{
				Response: nil,
				Err:      errors.New("network timeout"),
			},
			initialKeys:        nil,
			wantTrustedKeys:    map[string]ed25519.PublicKey{}, // Should remain empty
			wantErr:            true,
			wantErrMsgContains: "network timeout",
		},
		{
			name: "jwks endpoint returns error status",
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusInternalServerError, "Internal Server Error"),
				Err:      nil,
			},
			initialKeys:        nil,
			wantTrustedKeys:    map[string]ed25519.PublicKey{},
			wantErr:            true,
			wantErrMsgContains: "failed to fetch JWKS: status code 500",
		},
		{
			name: "invalid json response",
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, `{"keys": [invalid json}`),
				Err:      nil,
			},
			initialKeys:        nil,
			wantTrustedKeys:    map[string]ed25519.PublicKey{},
			wantErr:            true,
			wantErrMsgContains: "failed to Unmarshal response body",
		},
		{
			name: "load with pre-existing keys",
			mockClient: &MockJWSTClient{
				Response: NewMockHttpResponse(http.StatusOK, string(jwksJsonBody)),
				Err:      nil,
			},
			initialKeys: map[string]ed25519.PublicKey{
				"existing-key": ed25519.PublicKey([]byte("someotherkeybytes12345678901234")), // Example existing key
			},
			wantTrustedKeys: map[string]ed25519.PublicKey{
				"existing-key": ed25519.PublicKey([]byte("someotherkeybytes12345678901234")),
				validKid:       validPublicKey, // Should add the new key
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize Verifier with the mock client and initial keys
			v := &Verifier{
				JWSTClient:        tt.mockClient,
				trustedPublicKeys: make(map[string]ed25519.PublicKey), // Ensure a fresh map for each test run
			}
			// Copy initial keys if provided
			if tt.initialKeys != nil {
				for k, val := range tt.initialKeys {
					v.trustedPublicKeys[k] = val
				}
			}

			err := v.LoadKeys()

			// Check error expectation
			if (err != nil) != tt.wantErr {
				t.Errorf("Verifier.LoadKeys() error = %v, wantErr %v", err, tt.wantErr)
				return // Don't proceed if error expectation is wrong
			}
			// Optional: Check specific error message content
			if tt.wantErr && tt.wantErrMsgContains != "" && err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMsgContains) {
					t.Errorf("Verifier.LoadKeys() error = %q, want error containing %q", err.Error(), tt.wantErrMsgContains)
				}
			}

			// Check the state of trustedPublicKeys after loading
			if !reflect.DeepEqual(v.trustedPublicKeys, tt.wantTrustedKeys) {
				t.Errorf("Verifier.LoadKeys() trustedPublicKeys = %v, want %v", v.trustedPublicKeys, tt.wantTrustedKeys)
			}
		})
	}
}
