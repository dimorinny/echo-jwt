package jwt

import (
	"testing"
)

func TestTokenParser(t *testing.T) {
	tokenData := "ghsdfvovu4g3b2h4it.hu23h452462.2i4352345"
	prefix := "JWT"
	token := prefix + " " + tokenData

	if token, _ = getAuthTokenFromHeader(token, prefix); token != tokenData {
		t.Error("Error parsing token data with token: " + token)
	}
}

func TestTokenParserEmpty(t *testing.T) {
	prefix := "JWT"
	token := ""

	if token, err := getAuthTokenFromHeader(token, prefix); err == nil || token != "" {
		t.Error("Error parsing empty token")
	}
}

func TestTokenParserWithoutTokenData(t *testing.T) {
	prefix := "JWT"
	token := "JWT "

	if token, err := getAuthTokenFromHeader(token, prefix); err == nil || token != "" {
		t.Error("Error parsing token without data")
	}
}
