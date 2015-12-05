package jwt

import (
	"testing"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
)

const (
	testSecret   = "testSecret"
	testIdentity = "testIdentity"
	testDuration = time.Hour * 20
)

var (
	testMethod = gojwt.SigningMethodHS256
)

func TestValidation(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, testIdentity)
	token, err := decodeToken(testSecret, testMethod, tokenString)

	if !token.Valid {
		t.Error(err)
	}
}

func TestExpired(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, testIdentity)
	token, err := decodeToken(testSecret, testMethod, tokenString)

	if !token.Valid {
		t.Error(err)
	}

	if _, ok := token.Claims[expiredKey]; ok &&
		getExpiredFromClaims(token.Claims, expiredKey) != time.Now().Add(testDuration).Unix() {
		t.Error("Duration Error")
	}
}

func TestIdentity(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, testIdentity)
	token, err := decodeToken(testSecret, testMethod, tokenString)

	if !token.Valid {
		t.Error(err)
	}

	if _, ok := token.Claims[identityKey]; ok && testIdentity != token.Claims[identityKey] {
		t.Error("Read identity Error")
	}
}
