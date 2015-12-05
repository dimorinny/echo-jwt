package jwt

import (
	"time"

	gojwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
)

const (
	defaultExpDelta      = time.Hour * 100
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
		JwtExpirationDelta time.Duration
		secret             string
		UsernameField      string
		PasswordField      string
		IdentityKey        string
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
	}
}

func (jwt *Jwt) AuthRequired() echo.HandlerFunc {
	return func(c *echo.Context) error {

	}
}

func (jwt *Jwt) LoginHandler() echo.HandlerFunc {
	return func(c *echo.Context) error {
		return nil
	}
}
