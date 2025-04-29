package model

import "github.com/golang-jwt/jwt/v5"

// CustomClaims: このシステムにおける JWT のクレームを定義する構造体
type CustomClaims struct {
	jwt.RegisteredClaims
}

type Response struct {
	Keys []Key `json:"keys"`
}

type Key struct {
	Kty string `json:"kty"` // 鍵のタイプ
	Crv string `json:"crv"` // 鍵の曲線
	Kid string `json:"kid"` // 鍵のID
	Use string `json:"use"` // 鍵の用途
	Alg string `json:"alg"` // 鍵のアルゴリズム
	X   string `json:"x"`   // 鍵の値
}

type TokenResponse struct {
	// "token": "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0wMDEiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE3NjIxODQwMjIsImlzcyI6Imp3a3NfZGVtb19pc3N1ZXIifQ.b...",
	// "token_type": "Bearer",
	// "expires_in": 3600
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}
