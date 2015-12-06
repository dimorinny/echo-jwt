package jwt

import (
	"fmt"
	"net/http"
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
			fmt.Println("header empty or invalid")
			return nil
		}

		token, err := decodeToken(jwt.config.secret, tokenMethod, tokenString)

		if err != nil {
			// TODO: error token not valid
			fmt.Println("error token not valid")
			return nil
		}

		if getExpiredFromClaims(token.Claims, expiredKey) < time.Now().Unix() {
			// TODO: error token expire
			fmt.Println("error token expire")
			return nil
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
			// TODO: has no required fields error\
			fmt.Println("has no required fields error")
			c.String(http.StatusOK, "has no required fields error")
			return nil
		}

		val := jwt.authenticate(username, password)

		if val == nil {
			// TODO: auth error
			fmt.Println("auth error")
			c.String(http.StatusOK, "auth error")
			return nil
		}

		token, err := encodeToken(jwt.config.secret, tokenMethod, jwt.config.JwtExpirationDelta, val)

		if err != nil {
			// TODO: error encode token
			fmt.Println("error encode token")
			c.String(http.StatusOK, "error encode token")
			return nil
		}

		// TODO: call user callback response
		c.String(http.StatusOK, token)
		return nil
	}
}
