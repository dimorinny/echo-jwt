package jwt

import (
	"net/http"

	"github.com/labstack/echo"
)

func defaultAuthErrorHandler(c *echo.Context) {
	c.JSON(http.StatusForbidden, map[string]interface{}{
		"status": "Error",
		"error":  "Auth error",
	})
}

func defaultLoginResponseHandler(c *echo.Context, accessToken string, refreshToken string) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "Ok",
		"response": map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		},
	})
}

func defaultRefreshResponseHandler(c *echo.Context, accessToken string, refreshToken string) {
	c.JSON(http.StatusOK, map[string]interface{}{
		"status": "Ok",
		"response": map[string]interface{}{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
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
