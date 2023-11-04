package types

import (
	"crypto/ed25519"
	"github.com/golang-jwt/jwt/v5"
)

type AccessTokenClaims struct {
	Uid      string `json:"uid"`
	Verified bool   `json:"ver"`
	Services string `json:"svc"`
	Level    int    `json:"lvl"`
	jwt.RegisteredClaims
}

type DataTokenClaims struct {
	Name  string                 `json:"svc"`
	Level int                    `json:"lvl"`
	Uid   string                 `json:"uid"`
	Data  map[string]interface{} `json:"data"`
	jwt.RegisteredClaims
}

type KeyPair struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}
