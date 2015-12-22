package main

import (
	"net/http"

	"github.com/dimorinny/echo-jwt/jwt"
	"github.com/labstack/echo"
	mw "github.com/labstack/echo/middleware"
)

type (
	User struct {
		Name     string
		Password string
	}
)

const (
	secretKey = "SuperSecret"
)

var (
	users = map[string]User{
		"Dmitry": User{"Dmitry", "password"},
		"Alex":   User{"Alex", "password1"},
	}

	config = jwt.NewConfig(secretKey)
)

// Return identity for current user or nil
// In this example identity: Name
func auth(login string, password string) interface{} {
	if val, ok := users[login]; ok && val.Password == password {
		return val.Name
	}

	return nil
}

// Return user by identity or nil
// In this example identity: Name
func identity(val interface{}) interface{} {
	return users[val.(string)]
}

// Common handler
func accessible(c *echo.Context) error {
	return c.String(http.StatusOK, "No auth required for this route.\n")
}

// Restricted handler
func restricted(c *echo.Context) error {
	user := c.Get(config.IdentityKey).(User)
	return c.String(http.StatusOK, user.Name+" "+user.Password)
}

func main() {
	// Customize login field in login handler
	config.UsernameField = "email"
	// Customize success login response
	config.LoginResponseHandler = func(c *echo.Context, identity interface{}, accessToken string, refreshToken string) {
		c.JSON(http.StatusOK, map[string]interface{}{
			"custom": "Yes",
			"status": "Ok",
			"response": map[string]interface{}{
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			},
		})
	}

	jwt := jwt.NewJwt(config, auth, identity)

	e := echo.New()
	e.Use(mw.Logger())

	e.Get("/", accessible)
	e.Post("/login", jwt.LoginHandler())
	e.Post("/refresh", jwt.RefreshTokenHandler())

	// Restricted group
	r := e.Group("/restricted")
	r.Use(jwt.AuthRequired())
	r.Get("", restricted)

	// Start server
	e.Run(":1323")
}
