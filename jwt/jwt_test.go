package jwt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/labstack/echo"
	"github.com/stretchr/testify/assert"
)

const (
	testJwtSecret   = "testjwtsecret"
	testJwtIdentity = "identity"
)

func testAuthenticateHandler(username string, password string) interface{} {
	if username == "test" && password == "test" {
		return "test"
	}

	return nil
}

func testIdentityHandler(identity interface{}) interface{} {
	return identity
}

func testErrorHandler(code int, response string) ErrorHandler {
	return func(c *echo.Context) {
		c.String(code, response)
	}
}

// ====================================
// ======== Test Token Methods ========
// ====================================

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

// =====================================
// === Test Auth Required Middleware ===
// =====================================

func TestAuthRequiredInvalidToken(t *testing.T) {
	response := "invalid token"
	status := http.StatusForbidden

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.TokenInvalidHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.Authorization, config.AuthPrefix+" invalid token")
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.AuthRequired()

	// Ececute
	handler(c)

	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

func TestAuthRequiredExpiredHandler(t *testing.T) {
	response := "expired token"
	status := http.StatusForbidden

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.TokenExpireHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	tokenString, _ := Encode(config.secret, tokenMethod,
		Token{"identity", time.Now().Unix() - 1, AccessToken})

	req.Header.Set(echo.Authorization, config.AuthPrefix+" "+tokenString)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.AuthRequired()

	// Ececute
	handler(c)

	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

func TestAuthRequired(t *testing.T) {
	e := echo.New()
	config := NewConfig(testJwtSecret)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	tokenString, _ := Encode(config.secret, tokenMethod,
		Token{"identity", time.Now().Add(config.AccessExpirationDelta).Unix(), AccessToken})

	req.Header.Set(echo.Authorization, config.AuthPrefix+" "+tokenString)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.AuthRequired()

	// Ececute
	err := handler(c)
	assert.NoError(t, err)
}

func TestAuthRequiredInvalidHeader(t *testing.T) {
	response := "invalid header"
	status := http.StatusBadRequest

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.HeaderInvalidHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.AuthRequired()

	// Ececute
	handler(c)

	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

// =====================================
// ========= Test Auth Handler =========
// =====================================

func TestAuthHandlerInvalid(t *testing.T) {
	response := "auth error"
	status := http.StatusForbidden

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.AuthErrorHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.POST, "/", nil)
	req.Form = url.Values{}
	req.Form.Set(config.UsernameField, "invalid")
	req.Form.Set(config.PasswordField, "invalid")

	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.LoginHandler()

	// Ececute
	handler(c)
	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

func TestAuthHandlerValid(t *testing.T) {
	response := "auth error"
	status := http.StatusForbidden

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.AuthErrorHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.POST, "/", nil)
	req.Form = url.Values{}
	req.Form.Set(config.UsernameField, "test")
	req.Form.Set(config.PasswordField, "test")

	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.LoginHandler()

	// Ececute
	err := handler(c)
	assert.NoError(t, err)

	result := struct {
		Status   string
		Response struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
	}{}

	json.Unmarshal(rec.Body.Bytes(), &result)
	assert.Equal(t, result.Status, "Ok")

	token, _ := jwt.TokenFromString(result.Response.AccessToken)
	assert.Equal(t, token.Identity, "test")
	assert.False(t, token.IsExpired())
}

// =====================================
// ======== Test Refresh Handler =======
// =====================================

func TestRefreshHandlerInvalidHeader(t *testing.T) {
	response := "invalid header"
	status := http.StatusBadRequest

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.HeaderInvalidHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.RefreshTokenHandler()

	// Ececute
	handler(c)

	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

func TestRefreshHandlerInvalidToken(t *testing.T) {
	response := "invalid token"
	status := http.StatusForbidden

	e := echo.New()
	config := NewConfig(testJwtSecret)
	config.TokenInvalidHandler = testErrorHandler(status, response)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	req.Header.Set(echo.Authorization, config.AuthPrefix+" invalid token")
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.RefreshTokenHandler()

	// Ececute
	handler(c)

	assert.Equal(t, rec.Body.String(), response)
	assert.Equal(t, rec.Code, status)
}

func TestRefreshHandlerInvalidType(t *testing.T) {
	e := echo.New()
	config := NewConfig(testJwtSecret)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	tokenString, _ := Encode(config.secret, tokenMethod,
		Token{"test", time.Now().Add(config.RefreshExpirationDelta).Unix(), AccessToken})

	req.Header.Set(echo.Authorization, config.AuthPrefix+" "+tokenString)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.RefreshTokenHandler()

	// Ececute
	err := handler(c)
	assert.Error(t, err)
}

func TestRefreshHandler(t *testing.T) {
	e := echo.New()
	config := NewConfig(testJwtSecret)

	jwt := NewJwt(config, testAuthenticateHandler, testIdentityHandler)

	req, _ := http.NewRequest(echo.GET, "/", nil)
	tokenString, _ := Encode(config.secret, tokenMethod,
		Token{"test", time.Now().Add(config.RefreshExpirationDelta).Unix(), RefreshToken})

	req.Header.Set(echo.Authorization, config.AuthPrefix+" "+tokenString)
	rec := httptest.NewRecorder()

	c := echo.NewContext(req, echo.NewResponse(rec, e), e)
	handler := jwt.RefreshTokenHandler()

	// Ececute
	err := handler(c)
	assert.NoError(t, err)

	result := struct {
		Status   string
		Response struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
	}{}

	json.Unmarshal(rec.Body.Bytes(), &result)
	assert.Equal(t, result.Status, "Ok")

	token, _ := jwt.TokenFromString(result.Response.AccessToken)
	assert.Equal(t, token.Identity, "test")
	assert.False(t, token.IsExpired())
}
