package model

import "github.com/golang-jwt/jwt/v5"

// CustomClaims: このシステムにおける JWT のクレームを定義する構造体
type CustomClaims struct {
	jwt.RegisteredClaims
}
