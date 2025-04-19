package server

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
