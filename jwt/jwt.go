package jwt

import (
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

const (
	AccessToken = iota
	RefreshToken
)

var (
	tokenMethod = gojwt.SigningMethodHS256
)

type (
	AuthHandler     func(login string, password string) interface{}
	IdentityHandler func(identity interface{}) interface{}
	ErrorHandler    func(c *echo.Context)
	ResponseHandler func(c *echo.Context, accessToken string, refreshToken string)

	TokenType byte

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

		LoginNotRequiredFieldsHandler ErrorHandler
		AuthErrorHandler              ErrorHandler
		LoginResponseHandler          ResponseHandler
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

		defaultNotRequiredFieldsHandler,
		defaultAuthErrorHandler,
		defaultLoginResponseHandler,
	}
}

func (jwt *Jwt) GenerateAccessToken(identity interface{}) (string, error) {
	return encodeToken(jwt.config.secret, tokenMethod,
		jwt.config.AccessExpirationDelta, AccessToken, identity)
}

func (jwt *Jwt) GenerateRefreshToken(identity interface{}) (string, error) {
	return encodeToken(jwt.config.secret, tokenMethod,
		jwt.config.RefreshExpirationDelta, RefreshToken, identity)
}

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

		token, err := decodeToken(jwt.config.secret, tokenMethod, AccessToken, tokenString)

		if err != nil {
			jwt.config.TokenInvalidHandler(c)
			return err
		}

		if getExpiredFromClaims(token.Claims, expiredKey) < time.Now().Unix() {
			jwt.config.TokenExpireHandler(c)
			return err
		}

		c.Set(jwt.config.IdentityKey, jwt.identity(token.Claims[identityKey]))
		return nil
	}
}

func (jwt *Jwt) LoginHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		username := c.Form(jwt.config.UsernameField)
		password := c.Form(jwt.config.PasswordField)

		if username == "" || password == "" {
			jwt.config.LoginNotRequiredFieldsHandler(c)
			return nil
		}

		val := jwt.authenticate(username, password)

		if val == nil {
			jwt.config.AuthErrorHandler(c)
			return nil
		}

		accessToken, err := jwt.GenerateAccessToken(val)
		refreshToken, err := jwt.GenerateRefreshToken(val)

		if err != nil {
			return err
		}

		jwt.config.LoginResponseHandler(c, accessToken, refreshToken)
		return nil
	}
}

func (jwt *Jwt) RefreshTokenHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		auth := c.Request().Header.Get(echo.Authorization)
		tokenString, err := getAuthTokenFromHeader(auth, jwt.config.AuthPrefix)

		if err != nil {
			jwt.config.HeaderInvalidHandler(c)
			return err
		}

		token, err := decodeToken(jwt.config.secret, tokenMethod, RefreshToken, tokenString)

		if err != nil {
			jwt.config.TokenInvalidHandler(c)
			return err
		}

		if getExpiredFromClaims(token.Claims, expiredKey) < time.Now().Unix() {
			jwt.config.TokenExpireHandler(c)
			return err
		}

		accessToken, err := jwt.GenerateAccessToken(token.Claims[identityKey])
		refreshToken, err := jwt.GenerateRefreshToken(token.Claims[identityKey])

		if err != nil {
			return err
		}

		jwt.config.LoginResponseHandler(c, accessToken, refreshToken)
		return nil
	}
}
