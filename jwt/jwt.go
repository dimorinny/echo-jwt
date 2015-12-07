package jwt

import (
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

const (
	defaultExpDelta      = time.Hour * 100
	defaultAuthPrefix    = "JWT"
	defaultUsernameField = "username"
	defaultPasswordField = "password"
	defaultIdentityKey   = "identity"
)

var (
	tokenMethod = gojwt.SigningMethodHS256
)

type (
	AuthHandler     func(login string, password string) interface{}
	IdentityHandler func(identity interface{}) interface{}
	ErrorHandler    func(c *echo.Context)
	ResponseHandler func(c *echo.Context, token string)

	Config struct {
		secret             string
		JwtExpirationDelta time.Duration
		UsernameField      string
		PasswordField      string
		IdentityKey        string
		AuthPrefix         string

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
		defaultExpDelta,
		defaultUsernameField,
		defaultPasswordField,
		defaultIdentityKey,
		defaultAuthPrefix,

		defaultHeaderInvalidHandler,
		defaultTokenInvalidHandler,
		defaultTokenExpireHandler,

		defaultNotRequiredFieldsHandler,
		defaultAuthErrorHandler,
		defaultLoginResponseHandler,
	}
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

		token, err := decodeToken(jwt.config.secret, tokenMethod, tokenString)

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

		token, err := encodeToken(jwt.config.secret, tokenMethod, jwt.config.JwtExpirationDelta, val)

		if err != nil {
			return err
		}

		jwt.config.LoginResponseHandler(c, token)
		return nil
	}
}
