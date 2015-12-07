package jwt

import (
	"fmt"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
)

const (
	identityKey = "Identity"
	expiredKey  = "Expired"
)

func encodeToken(secret string, alg gojwt.SigningMethod,
	duration time.Duration, identity interface{}) (string, error) {
	t := gojwt.New(alg)

	t.Claims[identityKey] = identity
	t.Claims[expiredKey] = time.Now().Add(duration).Unix()

	return t.SignedString([]byte(secret))
}

func decodeToken(secret string, alg gojwt.SigningMethod, tokenString string) (gojwt.Token, error) {
	t, err := gojwt.Parse(tokenString, func(token *gojwt.Token) (interface{}, error) {
		if ok := token.Method == alg; !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	})

	return *t, err
}
