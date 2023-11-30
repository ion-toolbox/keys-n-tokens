package tokens

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/ion-toolbox/keys-n-tokens/keyring"
	"github.com/ion-toolbox/keys-n-tokens/types"
	"google.golang.org/grpc/metadata"
	"strconv"
	"strings"
)

func validToken(md *metadata.MD) bool {
	authorization := (*md)["authorization"]
	if len(authorization) < 1 {
		return false
	}
	tokenString := strings.TrimPrefix(authorization[0], "Bearer ")
	token, err := jwt.ParseWithClaims(tokenString, &types.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return keyring.SharedKeyRing().GetKeyPair("self").Public, nil
	})
	if err != nil {
		return false
	}
	if !token.Valid {
		return false
	}
	(*md).Append("user-id", token.Claims.(*types.AccessTokenClaims).Uid)
	(*md).Append("user-services", token.Claims.(*types.AccessTokenClaims).Services)
	(*md).Append("user-level", strconv.Itoa(token.Claims.(*types.AccessTokenClaims).Level))
	return true
}
