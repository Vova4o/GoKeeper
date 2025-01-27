package service

import (
	"context"
	"errors"
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
	FindUser(ctx context.Context, username string) (*models.User, error)
	CheckMasterPassword(ctx context.Context, userID int) (string, error)
	StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error
	GetRefreshTokens(ctx context.Context, userID int) ([]models.RefreshToken, error)
	SaveData(ctx context.Context, userID string, data models.Data) error
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

// AuthenticateUser аутентифицирует пользователя
func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (*models.UserRegesred, error) {
	// check if user exists
	user, err := s.stor.FindUser(ctx, username)
	if err != nil {
		s.logger.Error("Failed to find user: " + err.Error())
		return nil, err
	}

	// check if password is correct
	if !passwordhash.CheckPasswordHash(password, user.PasswordHash) {
		return nil, errors.New("invalid password")
	}

	// create access token
	accessToken, err := s.jwtService.CreateAccessToken(user.UserID, time.Minute*60)
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
    accessToken, err := s.jwtService.CreateAccessToken(userID, time.Minute*60)
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
func (s *Service) RecordData(ctx context.Context, userID string, data models.Data) error {
	// check if user exists
	_, err := s.stor.FindUser(ctx, userID)
	if err != nil {
		s.logger.Error("Failed to find user: " + err.Error())
		return err
	}

	err = s.stor.SaveData(ctx, userID, data)
	if err != nil {
		s.logger.Error("Failed to save data: " + err.Error())
		return err
	}

	return nil
}

// // ReadData читает данные по типу
// func (s *Service) ReadData(ctx context.Context, userID string) ([]*pb.Data, error) {
// 	return s.stor.ReadData(ctx, userID)
// }
