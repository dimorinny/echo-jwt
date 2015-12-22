package jwt

import (
	"errors"
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

const (
	defaultAccessExpDelta  = time.Hour * 10
	defaultRefreshExpDelta = time.Hour * 100
	defaultAuthPrefix      = "JWT"
	defaultUsernameField   = "username"
	defaultPasswordField   = "password"
	defaultIdentityKey     = "identity"
)

var (
	tokenMethod = gojwt.SigningMethodHS256
)

type (
	AuthHandler     func(login string, password string) interface{}
	IdentityHandler func(identity interface{}) interface{}
	ErrorHandler    func(c *echo.Context)
	ResponseHandler func(c *echo.Context, identity interface{}, accessToken string, refreshToken string)

	Config struct {
		secret        string
		UsernameField string
		PasswordField string
		IdentityKey   string
		AuthPrefix    string

		AccessExpirationDelta  time.Duration
		RefreshExpirationDelta time.Duration

		HeaderInvalidHandler ErrorHandler
		TokenInvalidHandler  ErrorHandler
		TokenExpireHandler   ErrorHandler

		AuthErrorHandler       ErrorHandler
		LoginResponseHandler   ResponseHandler
		RefreshResponseHandler ResponseHandler
	}

	Jwt struct {
		config       Config
		authenticate AuthHandler
		identity     IdentityHandler
	}
)

func NewJwt(config Config, authenticate AuthHandler, identity IdentityHandler) Jwt {
	return Jwt{config, authenticate, identity}
}

func NewConfig(secret string) Config {
	return Config{
		secret,
		defaultUsernameField,
		defaultPasswordField,
		defaultIdentityKey,
		defaultAuthPrefix,

		defaultAccessExpDelta,
		defaultRefreshExpDelta,

		defaultHeaderInvalidHandler,
		defaultTokenInvalidHandler,
		defaultTokenExpireHandler,

		defaultAuthErrorHandler,
		defaultLoginResponseHandler,
		defaultRefreshResponseHandler,
	}
}

// Generate access token from identity.
// Use this method for generating tokens in your handlers.
func (jwt *Jwt) GenerateAccessToken(identity interface{}) (string, error) {
	return Encode(jwt.config.secret, tokenMethod,
		Token{identity, time.Now().Add(jwt.config.AccessExpirationDelta).Unix(), AccessToken})
}

// Generate refresh token from identity.
// Use this method for generating tokens in your handlers.
func (jwt *Jwt) GenerateRefreshToken(identity interface{}) (string, error) {
	return Encode(jwt.config.secret, tokenMethod,
		Token{identity, time.Now().Add(jwt.config.RefreshExpirationDelta).Unix(), RefreshToken})
}

// Get token object from token string.
// Use this method for parsing token object from token header in your custom handlers.
func (jwt *Jwt) TokenFromString(tokenString string) (*Token, error) {
	return Decode(jwt.config.secret, tokenMethod, tokenString)
}

// Auth required middleware.
func (jwt *Jwt) AuthRequired() echo.HandlerFunc {
	return func(c *echo.Context) error {
		if (c.Request().Header.Get(echo.Upgrade)) == echo.WebSocket {
			return nil
		}

		auth := c.Request().Header.Get(echo.Authorization)
		tokenString, err := getAuthTokenFromHeader(auth, jwt.config.AuthPrefix)

		if err != nil {
			jwt.config.HeaderInvalidHandler(c)
			return err
		}

		token, err := Decode(jwt.config.secret, tokenMethod, tokenString)

		if err != nil {
			jwt.config.TokenInvalidHandler(c)
			return err
		}

		if token.Type != AccessToken {
			jwt.config.TokenInvalidHandler(c)
			return errors.New("Error token type")
		}

		if token.IsExpired() {
			jwt.config.TokenExpireHandler(c)
			return errors.New("Token expired")
		}

		c.Set(jwt.config.IdentityKey, jwt.identity(token.Identity))
		return nil
	}
}

// Login handler. Override authenticate function and return identity for user.
func (jwt *Jwt) LoginHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		username := c.Form(jwt.config.UsernameField)
		password := c.Form(jwt.config.PasswordField)

		val := jwt.authenticate(username, password)

		if val == nil {
			jwt.config.AuthErrorHandler(c)
			return errors.New("Auth error")
		}

		accessToken, err := jwt.GenerateAccessToken(val)
		refreshToken, err := jwt.GenerateRefreshToken(val)

		if err != nil {
			return err
		}

		jwt.config.LoginResponseHandler(c, val, accessToken, refreshToken)
		return nil
	}
}

// Refresh token handler.
// Use this handler for refreshing access and refresh tokens by old refresh token.
func (jwt *Jwt) RefreshTokenHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		auth := c.Request().Header.Get(echo.Authorization)
		tokenString, err := getAuthTokenFromHeader(auth, jwt.config.AuthPrefix)

		if err != nil {
			jwt.config.HeaderInvalidHandler(c)
			return err
		}

		token, err := Decode(jwt.config.secret, tokenMethod, tokenString)

		if err != nil {
			jwt.config.TokenInvalidHandler(c)
			return err
		}

		if token.Type != RefreshToken {
			jwt.config.TokenInvalidHandler(c)
			return errors.New("Error token type")
		}

		if token.IsExpired() {
			jwt.config.TokenExpireHandler(c)
			return errors.New("Token expired")
		}

		accessToken, err := jwt.GenerateAccessToken(token.Identity)
		refreshToken, err := jwt.GenerateRefreshToken(token.Identity)

		if err != nil {
			return err
		}

		jwt.config.RefreshResponseHandler(c, token.Identity, accessToken, refreshToken)
		return nil
	}
}
