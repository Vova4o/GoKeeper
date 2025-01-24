package service

import (
	"context"
	"strconv"
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
	CreateUser(ctx context.Context, user models.User) (int, error)
	SaveRefreshToken(ctx context.Context, userRefresh models.RefreshToken) error
	AuthenticateUser(ctx context.Context, username, password string) (bool, error)
	CheckMasterPassword(ctx context.Context, userID int) (string, error)
	StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error
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
	user.PasswordHash, err = passwordhash.HashPassword(user.PasswordHash)
	if err != nil {
		s.logger.Error("Failed to hash password: " + err.Error())
		return nil, err
	}

	userID, err := s.stor.CreateUser(ctx, user)
	if err != nil || userID == 0 {
		s.logger.Error("Failed to create user: " + err.Error())
		return nil, err
	}

	accessToken, err := s.jwtService.CreateAccessToken(userID, time.Minute*60)
	if err != nil {
		s.logger.Error("Failed to create access token: " + err.Error())
		return nil, err
	}

	refreshToken, err := s.jwtService.CreateRefreshToken(userID, time.Hour*24*7)
	if err != nil {
		s.logger.Error("Failed to create refresh token: " + err.Error())
		return nil, err
	}

	err = s.stor.SaveRefreshToken(ctx, models.RefreshToken{
		UserID:    userID,
		Token:     refreshToken,
		IsRevoked: false,
	})
	if err != nil {
		s.logger.Error("Failed to save refresh token: " + err.Error())
		return nil, err
	}

	return &models.UserRegesred{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// MasterPasswordCheckOrStore проверяет или сохраняет мастер-пароль
func (s *Service) MasterPasswordCheckOrStore(ctx context.Context, token, masterPassword string) (bool, error) {
	masterPasswordHash, err := passwordhash.HashPassword(masterPassword)
	if err != nil {
		s.logger.Error("Failed to hash master password: " + err.Error())
		return false, err
	}

	// get user ID from token
	userID, err := s.jwtService.UserIDFromToken(token)
	if err != nil {
		s.logger.Error("Failed to get user ID from token: " + err.Error())
		return false, err
	}

	// check if master password is already stored
	masterPasswordHashFromDB, err := s.stor.CheckMasterPassword(ctx, userID)
	if err != nil {
		if err.Error() == "record not found" {
			// if not stored, store it
			err = s.stor.StoreMasterPassword(ctx, userID, masterPasswordHash)
			if err != nil {
				s.logger.Error("Failed to store master password: " + err.Error())
				return false, err
			}
			return true, nil
		}
		s.logger.Error("Failed to check master password: " + err.Error())
		return false, err
	}

	// if stored, check if it is correct
	if passwordhash.CheckPasswordHash(masterPassword, masterPasswordHashFromDB) {
		// if correct, return true
		return true, nil
	}

	return false, nil
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

func stringToUint64(s string) (uint64, error) {
	var err error
	var res uint64
	res, err = strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return res, nil
}
