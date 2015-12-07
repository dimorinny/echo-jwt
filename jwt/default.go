package jwt

import (
	"net/http"

	"github.com/labstack/echo"
)

func defaultNotRequiredFieldsHandler(c *echo.Context) {
	c.JSON(http.StatusBadRequest, map[string]interface{}{
		"status": "Error",
		"error":  "Request has't required fields for authenticate",
	})
}

func defaultAuthErrorHandler(c *echo.Context) {
	c.JSON(http.StatusForbidden, map[string]interface{}{
		"status": "Error",
		"error":  "Auth error",
	})
}

func defaultLoginResponseHandler(c *echo.Context, token string) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "Ok",
		"response": map[string]interface{}{
			"token": token,
		},
	})
}

func defaultHeaderInvalidHandler(c *echo.Context) {
	c.JSON(http.StatusBadRequest, map[string]interface{}{
		"status": "Error",
		"error":  "Token header not found or has not valid format",
	})
}

func defaultTokenInvalidHandler(c *echo.Context) {
	c.JSON(http.StatusForbidden, map[string]interface{}{
		"status": "Error",
		"error":  "Token not valid",
	})
}

func defaultTokenExpireHandler(c *echo.Context) {
	c.JSON(http.StatusForbidden, map[string]interface{}{
		"status": "Error",
		"error":  "Token expired",
	})
}
