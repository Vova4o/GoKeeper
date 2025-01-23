package service

import (
	"context"
	"time"

	"goKeeperYandex/package/jwtauth"
	"goKeeperYandex/package/logger"
	"goKeeperYandex/package/passwordhash"

	"goKeeperYandex/internal/server/models"
)

// Service struct
type Service struct {
	stor       Storager
	jwtService *jwtauth.JWTService
	logger     *logger.Logger
}

// Storager that is interface to work with storage layer
type Storager interface {
	CreateUser(ctx context.Context, user models.User) (uint, error)
	SaveRefreshToken(ctx context.Context, userRefresh models.RefreshToken) error
	AuthenticateUser(ctx context.Context, username, password string) (bool, error)
}

// NewService создает новый экземпляр сервиса
func NewService(stor Storager, secretKey, issuer string, logger *logger.Logger) *Service {
	return &Service{
		stor:       stor,
		jwtService: jwtauth.NewJWTService(secretKey, issuer),
		logger:     logger,
	}
}

// RegisterUser регистрирует нового пользователя
func (s *Service) RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error) {
	var err error
	// need to hash password before sending it to DB
	user.Password, err = passwordhash.HashPassword(user.Password)
	if err != nil {
		s.logger.Error("Failed to hash password: " + err.Error())
		return nil, err
	}

	userID, err := s.stor.CreateUser(ctx, user)
	if err != nil || userID == 0 {
		s.logger.Error("Failed to create user: " + err.Error())
		return nil, err
	}

	accessToken, err := s.jwtService.CreateAccessToken(user.Username, time.Minute*60)
	if err != nil {
		s.logger.Error("Failed to create access token: " + err.Error())
		return nil, err
	}

	refreshToken, err := s.jwtService.CreateRefreshToken(user.Username, time.Hour*24*7)
	if err != nil {
		s.logger.Error("Failed to create refresh token: " + err.Error())
		return nil, err
	}

	// convert uint to uint64
	userID64 := uint64(userID)

	err = s.stor.SaveRefreshToken(ctx, models.RefreshToken{
		UserID:    userID64,
		Token:     refreshToken,
		IsRevoked: false,
	})
	if err != nil {
		s.logger.Error("Failed to save refresh token: " + err.Error())
		return nil, err
	}

	return &models.UserRegesred{
		UserID:       userID64,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// // AuthenticateUser аутентифицирует пользователя
// func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
// 	return s.stor.AuthenticateUser(ctx, username, password)
// }

// // RecordData записывает данные
// func (s *Service) RecordData(ctx context.Context, userID string, data *pb.Data) error {
// 	return s.stor.RecordData(ctx, userID, data)
// }

// // ReadData читает данные по типу
// func (s *Service) ReadData(ctx context.Context, userID string) ([]*pb.Data, error) {
// 	return s.stor.ReadData(ctx, userID)
// }
