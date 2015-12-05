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

	Config struct {
		secret             string
		JwtExpirationDelta time.Duration
		UsernameField      string
		PasswordField      string
		IdentityKey        string
		AuthPrefix         string
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

func Lol() int {
	return 10
}

func NewConfig(secret string) Config {
	return Config{
		secret,
		defaultExpDelta,
		defaultUsernameField,
		defaultPasswordField,
		defaultIdentityKey,
		defaultAuthPrefix,
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
			// TODO: header empty or invalid
		}

		token, err := decodeToken(jwt.config.secret, tokenMethod, tokenString)

		if err != nil {
			// TODO: error token not valid
		}

		if getExpiredFromClaims(token.Claims, expiredKey) < time.Now().Unix() {
			// TODO: error token expire
		}

		c.Set(jwt.config.IdentityKey, jwt.identity(token.Claims[identityKey]))
		return nil
	}
}

func (jwt *Jwt) LoginHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		return nil
	}
}
