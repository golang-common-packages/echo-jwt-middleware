package echojwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)
)

// Storage store function in jwt package
type Storage interface {
	Middleware(publicKey string) echo.MiddlewareFunc
	RefreshTokentMiddleware(publicKey string) echo.MiddlewareFunc
	CreateNewTokens(accessTokenPrivateKey, refreshTokenPrivateky, data, tokenType string, timeout int, isAdmin bool) (accessToken, refreshToken string, err error)
	GenerateAccessToken(privateKey, data, tokenType string, timeout int, isAdmin bool) (string, error)
	GenerateRefreshToken(privateKey, data, tokenType string, timeout int, isAdmin bool) (string, error)
	Validate(scope string, c echo.Context) error
}
