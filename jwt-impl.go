package jwtMiddleware

import (
	"crypto/rsa"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var (
	accessTokenSignKey     *rsa.PrivateKey
	accessTokenVerifyKey   *rsa.PublicKey
	refreshTokenSignKey    *rsa.PrivateKey
	refreshTokenVerifyKey  *rsa.PublicKey
	tokenWaitGroup         sync.WaitGroup
	accessTokenMiddleware  echo.MiddlewareFunc
	refreshTokenMiddleware echo.MiddlewareFunc
)

// Client manage all methods
type Client struct{}

// Middleware function will provide an echo middleware for jwt token
func (c *Client) Middleware(publicKey string) echo.MiddlewareFunc {
	if accessTokenMiddleware != nil {
		return accessTokenMiddleware
	}

	// Read public key
	bytes, err := ioutil.ReadFile(publicKey)
	if err != nil {
		panic(err)
	}

	// Parse public key
	accessTokenVerifyKey, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		panic(err)
	}

	jc := middleware.JWTConfig{
		Skipper: func(m echo.Context) bool {
			return false
		},
		ContextKey:    "user",
		SigningKey:    accessTokenVerifyKey,
		SigningMethod: "RS256", // Should use the same method when sign the access token
		TokenLookup:   "header:" + echo.HeaderAuthorization,
	}

	accessTokenMiddleware = middleware.JWTWithConfig(jc)
	return accessTokenMiddleware
}

// RefreshTokentMiddleware function will provide an echo middleware for refresh token
func (c *Client) RefreshTokentMiddleware(publicKey string) echo.MiddlewareFunc {
	if refreshTokenMiddleware != nil {
		return refreshTokenMiddleware
	}

	// Read public key
	bytes, err := ioutil.ReadFile(publicKey)
	if err != nil {
		panic(err)
	}

	// Parse public key
	refreshTokenVerifyKey, err := jwt.ParseRSAPublicKeyFromPEM(bytes)
	if err != nil {
		panic(err)
	}

	jc := middleware.JWTConfig{
		Skipper: func(m echo.Context) bool {
			return false
		},
		ContextKey:    "user",
		SigningKey:    refreshTokenVerifyKey,
		SigningMethod: "RS256", // Should use the same method when sign the refresh token
		TokenLookup:   "header:" + echo.HeaderAuthorization,
	}

	refreshTokenMiddleware = middleware.JWTWithConfig(jc)
	return refreshTokenMiddleware
}

// CreateNewTokens function will return access & refresh token
func (c *Client) CreateNewTokens(accessTokenPrivateKey, refreshTokenPrivateky, email, tokenType string, timeout int, isAdmin bool) (accessToken, refreshToken string, err error) {
	// Apply Goroutines for generate access and refresh token
	tokenWaitGroup.Add(2)
	go func() {
		accessToken, err = c.GenerateAccessToken(accessTokenPrivateKey, email, tokenType, timeout, isAdmin)
		if err != nil {
			panic(err)
		}
		tokenWaitGroup.Done()
	}()
	go func() {
		refreshToken, err = c.GenerateRefreshToken(refreshTokenPrivateky, email, tokenType, timeout, isAdmin)
		if err != nil {
			panic(err)
		}
		tokenWaitGroup.Done()
	}()
	tokenWaitGroup.Wait()

	return accessToken, refreshToken, nil
}

// GenerateAccessToken function will generate access token
func (c *Client) GenerateAccessToken(privateKey, email, tokenType string, timeout int, isAdmin bool) (string, error) {
	// Read private key

	bytes, err := ioutil.ReadFile(privateKey)
	if err != nil {
		return "", err
	}

	// Parse private key
	accessTokenSignKey, err = jwt.ParseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		return "", err
	}

	// Set custom claims
	claims := &JWTCustomClaims{
		email,
		tokenType,
		isAdmin,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(timeout)).Unix(),
		},
	}

	// Create token with claims based on RSA256 method
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Signed token by RSA521 key type
	encodedToken, err := token.SignedString(accessTokenSignKey)
	if err != nil {
		return "", err
	}

	return "Bearer " + encodedToken, nil
}

// GenerateRefreshToken function will generate refresh token
func (c *Client) GenerateRefreshToken(privateKey, email, tokenType string, timeout int, isAdmin bool) (string, error) {
	// Read private key
	bytes, err := ioutil.ReadFile(privateKey)
	if err != nil {
		return "", err
	}

	// Parse private key
	refreshTokenSignKey, err = jwt.ParseRSAPrivateKeyFromPEM(bytes)
	if err != nil {
		return "", err
	}

	// Set custom claims
	claims := &JWTCustomClaims{
		email,
		tokenType,
		isAdmin,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(timeout)).Unix(),
		},
	}

	// Create token with claims based on RSA256 method
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Signed token by RSA256 key type
	encodedToken, err := token.SignedString(refreshTokenSignKey)
	if err != nil {
		return "", err
	}

	return "Bearer " + encodedToken, nil
}

// Validate function will validate for an authentication request
func (c *Client) Validate(scope string, e echo.Context) error {
	token, ok := e.Get("user").(*jwt.Token)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unable to get token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unable to read claims")
	}

	cscope, ok := claims["scope"].(string)
	if !ok {
		return echo.NewHTTPError(http.StatusUnauthorized, "unable to read claims")
	}

	if !strings.Contains(cscope, scope) {
		return echo.NewHTTPError(http.StatusUnauthorized, "insufficient scope")
	}

	return nil
}

// GetEmailFromContext function will decode JWT and get email
func (c *Client) GetEmailFromContext(e echo.Context) string {
	user := e.Get("user")
	if user == nil {
		return ""
	}

	token := user.(*jwt.Token)
	if token == nil {
		return ""
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims == nil {
		return ""
	}

	email := claims["email"].(string)

	return email
}

// GetTokenTypeFromContext function will decode JWT and get email
func (c *Client) GetTokenTypeFromContext(e echo.Context) string {
	user := e.Get("user")
	if user == nil {
		return ""
	}

	token := user.(*jwt.Token)
	if token == nil {
		return ""
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims == nil {
		return ""
	}

	tokenType := claims["tokenType"].(string)

	return tokenType
}
