package jwt

import (
	"testing"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
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
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, AccessToken, testIdentity)
	_, err := decodeToken(testSecret, testMethod, AccessToken, tokenString)

	assert.NoError(t, err)
}

func TestRefreshFlagError(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, RefreshToken, testIdentity)
	_, err := decodeToken(testSecret, testMethod, AccessToken, tokenString)

	assert.Error(t, err, "Error refresh flag parsing not detected")
}

func TestExpired(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, AccessToken, testIdentity)
	token, err := decodeToken(testSecret, testMethod, AccessToken, tokenString)

	assert.NoError(t, err)

	if _, ok := token.Claims[expiredKey]; ok &&
		getExpiredFromClaims(token.Claims, expiredKey) != time.Now().Add(testDuration).Unix() {
		t.Error("Duration Error")
	}
}

func TestIdentity(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, AccessToken, testIdentity)
	token, err := decodeToken(testSecret, testMethod, AccessToken, tokenString)

	assert.NoError(t, err)

	if _, ok := token.Claims[identityKey]; ok && testIdentity != token.Claims[identityKey] {
		t.Error("Read identity Error")
	}
}

func TestRefresh(t *testing.T) {
	tokenString, _ := encodeToken(testSecret, testMethod, testDuration, AccessToken, testIdentity)
	token, err := decodeToken(testSecret, testMethod, AccessToken, tokenString)

	assert.NoError(t, err)
	assert.NotEqual(t, getTokenTypeFromClaims(token.Claims, tokenTypeKey),
		AccessToken, "Read refresh flag from token error")
}
