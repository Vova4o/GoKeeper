package jwtauth

import (
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
)

func TestNewJWTService(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	assert.Equal(t, secretKey, service.secretKey)
	assert.Equal(t, issuer, service.issuer)
}

func TestCreateAccessToken(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	userID := 1
	duration := time.Minute * 60
	token, err := service.CreateAccessToken(userID, duration)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := service.ParseToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, int(claims["user_id"].(float64)))
	assert.Equal(t, "access", claims["type"])
	assert.Equal(t, issuer, claims["iss"])
}

func TestCreateRefreshToken(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	userID := 1
	duration := time.Hour * 24 * 7
	token, err := service.CreateRefreshToken(userID, duration)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := service.ParseToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, int(claims["user_id"].(float64)))
	assert.Equal(t, "refresh", claims["type"])
	assert.Equal(t, issuer, claims["iss"])
}

func TestUserIDFromToken(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	userID := 1
	duration := time.Minute * 60
	token, err := service.CreateAccessToken(userID, duration)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	extractedUserID, err := service.UserIDFromToken(token)
	assert.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)
}

func TestParseToken_InvalidToken(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	invalidToken := "invalid.token.string"
	claims, err := service.ParseToken(invalidToken)

	assert.Error(t, err)
	assert.Nil(t, claims)
}

func TestParseToken_InvalidIssuer(t *testing.T) {
	secretKey := "secret"
	issuer := "issuer"
	service := NewJWTService(secretKey, issuer)

	userID := 1
	duration := time.Minute * 60
	token, err := service.CreateAccessToken(userID, duration)

	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// Modify the token to have an invalid issuer
	parsedToken, _ := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	claims := parsedToken.Claims.(jwt.MapClaims)
	claims["iss"] = "invalid_issuer"
	invalidToken, _ := parsedToken.SignedString([]byte(secretKey))

	parsedClaims, err := service.ParseToken(invalidToken)
	assert.Error(t, err)
	assert.Nil(t, parsedClaims)
}
