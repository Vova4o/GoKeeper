package service

import (
	"context"
	"database/sql"
	"errors"
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
	DeleteRefreshToken(ctx context.Context, token string) error
	FindUserByID(ctx context.Context, userID int) (*models.User, error)
	FindUserByName(ctx context.Context, username string) (*models.User, error)
	CheckMasterPassword(ctx context.Context, userID int) (string, error)
	StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error
	GetRefreshTokens(ctx context.Context, userID int) ([]models.RefreshToken, error)
	SaveData(ctx context.Context, userID int, dataType models.DataType, data string) error
	ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.PrivateInfo, error)
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

	// TODO: move time to config
	accessToken, err := s.jwtService.CreateAccessToken(userID, time.Minute*15)
	if err != nil {
		s.logger.Error("Failed to create access token: " + err.Error())
		return nil, err
	}

	// TODO: move time to config
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
func (s *Service) MasterPasswordCheckOrStore(ctx context.Context, masterPassword string) (bool, error) {
	masterPasswordHash, err := passwordhash.HashPassword(masterPassword)
	if err != nil {
		s.logger.Error("Failed to hash master password: " + err.Error())
		return false, err
	}

	// userID from context
	userID, ok := ctx.Value(models.UserIDKey).(int)
	if !ok {
		s.logger.Error("Failed to get user ID from context")
		return false, errors.New("failed to get user ID from context")
	}

	s.logger.Info("User ID: " + strconv.Itoa(userID))

	// check if master password is already stored
	masterPasswordHashFromDB, err := s.stor.CheckMasterPassword(ctx, userID)
	if err != nil && err != sql.ErrNoRows {
		s.logger.Error("Failed to check master password: " + err.Error())
		return false, err
	}

	// if not stored, store it
	if masterPasswordHashFromDB == "" {
		s.logger.Info("Master password not found, storing...")
		err = s.stor.StoreMasterPassword(ctx, userID, masterPasswordHash)
		if err != nil {
			s.logger.Error("Failed to store master password: " + err.Error())
			return false, err
		}
		return true, nil
	}

	// if stored, check if it is correct
	if passwordhash.CheckPasswordHash(masterPassword, masterPasswordHashFromDB) {
		s.logger.Info("Master password correct and stored")
		// if correct, return true
		return true, nil
	}

	return false, nil
}

// AuthenticateUser аутентифицирует пользователя
func (s *Service) AuthenticateUser(ctx context.Context, username string, password string) (*models.UserRegesred, error) {
	s.logger.Info("Authenticating user: " + username)

	// check if user exists
	user, err := s.stor.FindUserByName(ctx, username)
	if err != nil {
		s.logger.Error("Failed to find user: " + err.Error())
		return nil, err
	}

	// check if password is correct
	if !passwordhash.CheckPasswordHash(password, user.PasswordHash) {
		s.logger.Error("Invalid password")
		return nil, errors.New("invalid password")
	}

	// create access token
	accessToken, err := s.jwtService.CreateAccessToken(user.UserID, time.Minute*15)
	if err != nil {
		s.logger.Error("Failed to create access token: " + err.Error())
		return nil, err
	}

	// create refresh token
	refreshToken, err := s.jwtService.CreateRefreshToken(user.UserID, time.Hour*24*7)
	if err != nil {
		s.logger.Error("Failed to create refresh token: " + err.Error())
		return nil, err
	}

	err = s.stor.SaveRefreshToken(ctx, models.RefreshToken{
		UserID:    user.UserID,
		Token:     refreshToken,
		IsRevoked: false,
	})
	if err != nil {
		s.logger.Error("Failed to save refresh token: " + err.Error())
		return nil, err
	}

	return &models.UserRegesred{
		UserID:       user.UserID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken обновляет токены доступа и обновления
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*models.UserRegesred, error) {
	// parse the token
	claims, err := s.jwtService.ParseToken(refreshToken)
	if err != nil {
		s.logger.Error("Error parsing token: " + err.Error())
		if err.Error() == "Token is expired" {
			// delete expired token from DB
			err = s.stor.DeleteRefreshToken(ctx, refreshToken)
			if err != nil {
				s.logger.Error("Failed to delete expired refresh token: " + err.Error())
			}
			return nil, errors.New("refresh token expired")
		}
		s.logger.Error("Failed to parse refresh token: " + err.Error())
		return nil, err
	}

	if claims == nil {
		return nil, errors.New("invalid token, claims nil")
	}

	// get user ID from token
	userID, err := s.jwtService.UserIDFromToken(refreshToken)
	if err != nil {
		s.logger.Error("Failed to get user ID from token: " + err.Error())
		return nil, err
	}

	// check if refresh token is revoked
	refreshTokensFromDB, err := s.stor.GetRefreshTokens(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to get refresh tokens: " + err.Error())
		return nil, err
	}

	var validToken *models.RefreshToken
	for _, token := range refreshTokensFromDB {
		if token.Token == refreshToken {
			if token.IsRevoked {
				// delete revoked token from DB
				err = s.stor.DeleteRefreshToken(ctx, refreshToken)
				if err != nil {
					s.logger.Error("Failed to delete revoked refresh token: " + err.Error())
					return nil, err
				}
				return nil, errors.New("refresh token revoked")
			}

			validToken = &token
			break
		}
	}

	if validToken == nil {
		return nil, errors.New("invalid refresh token")
	}

	// create new access token
	accessToken, err := s.jwtService.CreateAccessToken(userID, time.Minute*15)
	if err != nil {
		s.logger.Error("Failed to create access token: " + err.Error())
		return nil, err
	}

	// create new refresh token
	newRefreshToken, err := s.jwtService.CreateRefreshToken(userID, time.Hour*24*7)
	if err != nil {
		s.logger.Error("Failed to create refresh token: " + err.Error())
		return nil, err
	}

	// save new refresh token
	err = s.stor.SaveRefreshToken(ctx, models.RefreshToken{
		UserID:    userID,
		Token:     newRefreshToken,
		IsRevoked: false,
	})
	if err != nil {
		s.logger.Error("Failed to save new refresh token: " + err.Error())
		return nil, err
	}

	return &models.UserRegesred{
		UserID:       userID,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
	}, nil
}

// RecordData записывает данные
func (s *Service) RecordData(ctx context.Context, userID int, data models.DataToPass) error {
	// check if user exists
	_, err := s.stor.FindUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to find user: " + err.Error())
		return err
	}

	// Сохранение данных в базу данных (пример)
	err = s.stor.SaveData(ctx, userID, data.DataType, data.Data)
	if err != nil {
		s.logger.Error("Failed to save data: " + err.Error())
		return err
	}

	return nil
}

// ReadData читает данные по типу
func (s *Service) ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.DataToPass, error) {
	// check if user exists
	_, err := s.stor.FindUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to find user: " + err.Error())
		return nil, err
	}

	// Чтение данных из базы данных (пример)
	privateInfos, err := s.stor.ReadData(ctx, userID, dataType)
	if err != nil {
		s.logger.Error("Failed to get data: " + err.Error())
		return nil, err
	}

	var dataList []*models.DataToPass
	for _, privateInfo := range privateInfos {
		dataList = append(dataList, &models.DataToPass{
			DBID:     privateInfo.DBID,
			DataType: dataType,
			Data:     privateInfo.Data,
		})
	}

	return dataList, nil
}
