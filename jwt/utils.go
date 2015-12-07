package jwt

import (
	"errors"
)

func getExpiredFromClaims(claims map[string]interface{}, key string) int64 {
	return int64(claims[key].(float64))
}

func getTokenTypeFromClaims(claims map[string]interface{}, key string) TokenType {
	return TokenType(claims[key].(float64))
}

func getAuthTokenFromHeader(auth string, prefix string) (string, error) {
	prefixLength := len(prefix)

	if len(auth) > prefixLength+1 && auth[:prefixLength] == prefix {
		return auth[prefixLength+1:], nil
	} else {
		return "", errors.New("Error while parsing token")
	}
}
