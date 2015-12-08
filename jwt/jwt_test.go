package jwt

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	testJwtSecret   = "testjwtsecret"
	testJwtIdentity = "identity"
)

func testAuthenticateHandler(username string, password string) interface{} {
	return "identity"
}

func testIdentityHandler(identity interface{}) interface{} {
	return identity
}

func TestAccessToken(t *testing.T) {
	jwt := NewJwt(NewConfig(testJwtSecret), testAuthenticateHandler, testIdentityHandler)
	expTimestamp := time.Now().Add(jwt.config.AccessExpirationDelta).Unix()
	tokenString, err := jwt.GenerateAccessToken(testJwtIdentity)

	// Should not be error.
	assert.NoError(t, err)

	token, err := jwt.TokenFromString(tokenString)

	// Should not be error.
	assert.NoError(t, err)
	assert.Equal(t, token.Identity, testJwtIdentity)
	assert.Equal(t, token.Type, AccessToken)
	assert.Equal(t, token.UnixTimestamp, expTimestamp)
}

func TestRefreshToken(t *testing.T) {
	jwt := NewJwt(NewConfig(testJwtSecret), testAuthenticateHandler, testIdentityHandler)
	expTimestamp := time.Now().Add(jwt.config.RefreshExpirationDelta).Unix()
	tokenString, err := jwt.GenerateRefreshToken(testJwtIdentity)

	// Should not be error.
	assert.NoError(t, err)

	token, err := jwt.TokenFromString(tokenString)

	// Should not be error.
	assert.NoError(t, err)
	assert.Equal(t, token.Identity, testJwtIdentity)
	assert.Equal(t, token.Type, RefreshToken)
	assert.Equal(t, token.UnixTimestamp, expTimestamp)
}
