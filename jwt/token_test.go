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
)

var (
	testExpTime = time.Now().Add(time.Hour * 20).Unix()
	testMethod  = gojwt.SigningMethodHS256
)

func TestValidation(t *testing.T) {
	_, err := Encode(testSecret, testMethod, Token{testIdentity, testExpTime, AccessToken})
	assert.NoError(t, err)
}

func TestTokenData(t *testing.T) {
	testToken := Token{testIdentity, testExpTime, RefreshToken}

	tokenString, err := Encode(testSecret, testMethod, testToken)
	assert.NoError(t, err)

	token, err := Decode(testSecret, testMethod, tokenString)
	assert.NoError(t, err)

	assert.Equal(t, testToken, *token)
}

func InvalidTokenTest(t *testing.T) {
	_, err := Decode(testSecret, testMethod, "invalidtoken")
	assert.Error(t, err)
}

func TestTokenDataError(t *testing.T) {
	testToken := Token{testIdentity, testExpTime, RefreshToken}

	tokenString, err := Encode(testSecret, testMethod, testToken)
	assert.NoError(t, err)

	token, err := Decode(testSecret, testMethod, tokenString)
	assert.NoError(t, err)

	token.UnixTimestamp += 1
	assert.NotEqual(t, testToken, *token)
}

func TestExpired(t *testing.T) {
	testToken := Token{testIdentity, time.Now().Unix() - 1, RefreshToken}

	tokenString, err := Encode(testSecret, testMethod, testToken)
	assert.NoError(t, err)

	token, err := Decode(testSecret, testMethod, tokenString)
	assert.NoError(t, err)

	assert.True(t, token.IsExpired())
}
