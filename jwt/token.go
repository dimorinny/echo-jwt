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

const (
	AccessToken = iota
	RefreshToken
)

type (
	TokenType byte

	Token struct {
		Identity      interface{}
		UnixTimestamp int64
		Type          TokenType
	}
)

func (t *Token) IsExpired() bool {
	return t.UnixTimestamp < time.Now().Unix()
}

func Encode(secret string, alg gojwt.SigningMethod, token Token) (string, error) {
	t := gojwt.New(alg)

	t.Claims[identityKey] = token.Identity
	t.Claims[expiredKey] = token.UnixTimestamp
	t.Claims[tokenTypeKey] = token.Type

	return t.SignedString([]byte(secret))
}

func Decode(secret string, alg gojwt.SigningMethod, tokenString string) (*Token, error) {
	token, err := decodeToken(secret, alg, tokenString)

	if err != nil {
		return nil, err
	}

	return &Token{
		token.Claims[identityKey],
		getExpiredFromClaims(token.Claims, expiredKey),
		getTokenTypeFromClaims(token.Claims, tokenTypeKey),
	}, nil
}

func decodeToken(secret string, alg gojwt.SigningMethod, tokenString string) (*gojwt.Token, error) {
	t, err := gojwt.Parse(tokenString, func(token *gojwt.Token) (interface{}, error) {
		if ok := token.Method == alg; !ok {
			return nil, errors.New("Unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	if !t.Valid {
		return nil, errors.New("Token invalid")
	}

	return t, err
}
