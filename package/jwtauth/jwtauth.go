package jwtauth

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// JWTService struct
type JWTService struct {
	secretKey string
	issuer    string
}

// NewJWTService creates a new JWTService instance
func NewJWTService(secretKey, issuer string) *JWTService {
	return &JWTService{
		secretKey: secretKey,
		issuer:    issuer,
	}
}

// CreateToken creates a new JWT token with additional claims
func (s *JWTService) CreateToken(tokenType string, duration time.Duration, additionalClaims jwt.MapClaims) (string, error) {
	claims := jwt.MapClaims{
		"type": tokenType,
		"exp":  time.Now().UTC().Add(duration).Unix(),
		"iss":  s.issuer,
	}

	for key, value := range additionalClaims {
		claims[key] = value
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.secretKey))
}

// CreateAccessToken creates an access token with user ID
func (s *JWTService) CreateAccessToken(userID string, timer time.Duration) (string, error) {
	additionalClaims := jwt.MapClaims{
		"user_id": userID,
	}
	return s.CreateToken("access", timer, additionalClaims)
}

// CreateRefreshToken creates a refresh token with user ID
func (s *JWTService) CreateRefreshToken(userID string, timer time.Duration) (string, error) {
	additionalClaims := jwt.MapClaims{
		"user_id": userID,
	}
	return s.CreateToken("refresh", timer, additionalClaims)
}

// UserIDFromToken returns the user ID from the token
func (s *JWTService) UserIDFromToken(tokenString string) (string, error) {
	claims, err := s.ParseToken(tokenString)
	if err != nil {
		return "", err
	}
	userID := claims["user_id"].(string)
	return userID, nil
}

// ParseToken parses and validates a JWT token
func (s *JWTService) ParseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(s.secretKey), nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if claims["iss"] != s.issuer {
			return nil, errors.New("invalid token issuer")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
