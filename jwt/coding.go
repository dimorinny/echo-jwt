package jwt

import (
	"errors"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
)

const (
	identityKey  = "Identity"
	expiredKey   = "Expired"
	tokenTypeKey = "TokenType"
)

func encodeToken(secret string, alg gojwt.SigningMethod,
	duration time.Duration, tokenType TokenType, identity interface{}) (string, error) {
	t := gojwt.New(alg)

	t.Claims[identityKey] = identity
	t.Claims[expiredKey] = time.Now().Add(duration).Unix()
	t.Claims[tokenTypeKey] = tokenType

	return t.SignedString([]byte(secret))
}

func decodeToken(secret string, alg gojwt.SigningMethod, tokenType TokenType,
	tokenString string) (*gojwt.Token, error) {
	t, err := gojwt.Parse(tokenString, func(token *gojwt.Token) (interface{}, error) {
		if ok := token.Method == alg; !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(secret), nil
	})

	if !t.Valid || getTokenTypeFromClaims(t.Claims, tokenTypeKey) != tokenType {
		return nil, errors.New("Token invalid")
	}

	return t, err
}
