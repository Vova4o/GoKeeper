package storage

import (
	"context"
	"database/sql"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/logger"

	_ "github.com/lib/pq"
)

// Storage struct
type Storage struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewStorage создает новый экземпляр хранилища
func NewStorage(ctx context.Context, connString string, logger *logger.Logger) (*Storage, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	// Проверка соединения
	if err := db.PingContext(ctx); err != nil {
		logger.Error("Failed to connect to the database")
		return nil, err
	}

	logger.Info("Connected to the database")
	return &Storage{
		db:     db,
		logger: logger,
	}, nil
}

// CreateUser создает нового пользователя
func (s *Storage) CreateUser(ctx context.Context, user models.User) (uint, error) {
	query := `INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id`
	var userID uint
	err := s.db.QueryRowContext(ctx, query, user.Username, user.PasswordHash).Scan(&userID)
	if err != nil {
		s.logger.Error("Failed to create user")
		return 0, err
	}

	s.logger.Info("User created successfully")
	return userID, nil
}

// SaveRefreshToken сохраняет refresh токен
func (s *Storage) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token, is_revoked) VALUES ($1, $2, $3)`
	_, err := s.db.ExecContext(ctx, query, token.UserID, token.Token, token.IsRevoked)
	if err != nil {
		s.logger.Error("Failed to save refresh token")
		return err
	}

	s.logger.Info("Refresh token saved successfully")
	return nil
}

// AuthenticateUser аутентифицирует пользователя
func (s *Storage) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
	query := `SELECT password_hash FROM users WHERE username = $1`
	var passwordHash string
	err := s.db.QueryRowContext(ctx, query, username).Scan(&passwordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		s.logger.Error("Failed to authenticate user")
		return false, err
	}

	if passwordHash != password {
		s.logger.Info("Password is incorrect")
		return false, nil
	}

	return true, nil
}

// CheckMasterPassword проверяет мастер-пароль
func (s *Storage) CheckMasterPassword(ctx context.Context, userID uint64) (string, error) {
	query := `SELECT master_password_hash FROM users WHERE id = $1`
	var masterPasswordHash string
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&masterPasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		s.logger.Error("Failed to check master password")
		return "", err
	}

	return masterPasswordHash, nil
}

// StoreMasterPassword сохраняет мастер-пароль
func (s *Storage) StoreMasterPassword(ctx context.Context, userID uint64, masterPasswordHash string) error {
	query := `UPDATE users SET master_password_hash = $1 WHERE id = $2`
	_, err := s.db.ExecContext(ctx, query, masterPasswordHash, userID)
	if err != nil {
		s.logger.Error("Failed to store master password")
		return err
	}

	s.logger.Info("Master password stored successfully")
	return nil
}

// Close закрывает соединение с базой данных
func (s *Storage) Close(ctx context.Context) error {
	return s.db.Close()
}

// package storage

// import (
// 	"context"
// 	"errors"

// 	"goKeeperYandex/internal/server/models"
// 	"goKeeperYandex/package/logger"
// 	pb "goKeeperYandex/protobuf/auth"

// 	"gorm.io/driver/postgres"
// 	"gorm.io/gorm"
// )

// // Storage struct
// type Storage struct {
// 	db     *gorm.DB
// 	logger *logger.Logger
// }

// // NewStorage создает новый экземпляр хранилища
// func NewStorage(ctx context.Context, connString string, logger *logger.Logger) (*Storage, error) {
// 	db, err := gorm.Open(postgres.Open(connString), &gorm.Config{})
// 	if err != nil {
// 		logger.Error("Failed to connect to the database: " + err.Error())
// 		return nil, err
// 	}

// 	// Автоматическая миграция схемы
// 	err = db.AutoMigrate(&models.User{}, &models.PrivateInfo{}, &models.RefreshToken{})
// 	if err != nil {
// 		logger.Error("Failed to migrate the schema: " + err.Error())
// 		return nil, err
// 	}

// 	logger.Info("Connected to the database")
// 	return &Storage{
// 		db:     db,
// 		logger: logger,
// 	}, nil
// }

// // CreateUser создает нового пользователя
// func (s *Storage) CreateUser(ctx context.Context, user models.User) (uint, error) {

// 	result := s.db.WithContext(ctx).Create(&user)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to create user: " + result.Error.Error())
// 		return 0, result.Error
// 	}

// 	// Возвращаем ID созданного пользователя
// 	s.logger.Info("User created successfully")
// 	return user.ID, nil
// }

// // SaveRefreshToken сохраняет refresh токен
// func (s *Storage) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
// 	result := s.db.WithContext(ctx).Create(&token)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to save refresh token: " + result.Error.Error())
// 		return result.Error
// 	}

// 	s.logger.Info("Refresh token saved successfully")
// 	return nil
// }

// // AuthenticateUser аутентифицирует пользователя
// func (s *Storage) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
// 	var user models.User
// 	result := s.db.WithContext(ctx).Where("username = ?", username).First(&user)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to authenticate user: " + result.Error.Error())
// 		return false, result.Error
// 	}

// 	if user.PasswordHash != password {
// 		return false, nil
// 	}

// 	return true, nil
// }

// // CheckMasterPassword проверяет мастер-пароль
// func (s *Storage) CheckMasterPassword(ctx context.Context, userID uint64) (string, error) {
// 	var user models.User
// 	result := s.db.WithContext(ctx).Where("id = ?", userID).First(&user)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to check master password: " + result.Error.Error())
// 		return "", result.Error
// 	}

// 	return user.MasterPasswordHash, nil
// }

// // StoreMasterPassword сохраняет мастер-пароль
// func (s *Storage) StoreMasterPassword(ctx context.Context, userID uint64, masterPasswordHash string) error {
// 	result := s.db.WithContext(ctx).Model(&models.User{}).Where("id = ?", userID).Update("master_password_hash", masterPasswordHash)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to store master password: " + result.Error.Error())
// 		return result.Error
// 	}

// 	s.logger.Info("Master password stored successfully")
// 	return nil
// }

// // RecordData записывает данные
// func (s *Storage) RecordData(ctx context.Context, userID string, data *pb.Data) error {
// 	privateInfo := models.PrivateInfo{
// 		UserID:   userID,
// 		DataType: data.DataType.String(),
// 	}

// 	switch v := data.Data.(type) {
// 	case *pb.Data_LoginPassword:
// 		privateInfo.Data = v.LoginPassword.String()
// 	case *pb.Data_TextNote:
// 		privateInfo.Data = v.TextNote.Text
// 	case *pb.Data_BinaryData:
// 		privateInfo.Data = string(v.BinaryData.Data)
// 	case *pb.Data_BankCard:
// 		privateInfo.Data = v.BankCard.String()
// 	default:
// 		return errors.New("unknown data type")
// 	}

// 	result := s.db.WithContext(ctx).Create(&privateInfo)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to record data: " + result.Error.Error())
// 		return result.Error
// 	}

// 	s.logger.Info("Data recorded successfully")
// 	return nil
// }

// // ReadData читает данные по типу
// func (s *Storage) ReadData(ctx context.Context, userID string) ([]*pb.Data, error) {
// 	var privateInfos []models.PrivateInfo
// 	result := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&privateInfos)
// 	if result.Error != nil {
// 		s.logger.Error("Failed to read data: " + result.Error.Error())
// 		return nil, result.Error
// 	}

// 	var data []*pb.Data
// 	for _, info := range privateInfos {
// 		var d pb.Data
// 		d.DataType = pb.DataType(pb.DataType_value[info.DataType])
// 		switch info.DataType {
// 		case pb.DataType_LOGIN_PASSWORD.String():
// 			d.Data = &pb.Data_LoginPassword{LoginPassword: &pb.LoginPassword{}}
// 		case pb.DataType_TEXT_NOTE.String():
// 			d.Data = &pb.Data_TextNote{TextNote: &pb.TextNote{Text: info.Data}}
// 		case pb.DataType_BINARY_DATA.String():
// 			d.Data = &pb.Data_BinaryData{BinaryData: &pb.BinaryData{Data: []byte(info.Data)}}
// 		case pb.DataType_BANK_CARD.String():
// 			d.Data = &pb.Data_BankCard{BankCard: &pb.BankCard{}}
// 		default:
// 			return nil, errors.New("unknown data type")
// 		}
// 		data = append(data, &d)
// 	}

// 	s.logger.Info("Data read successfully")
// 	return data, nil
// }

// // Close закрывает соединение с базой данных
// func (s *Storage) Close(ctx context.Context) error {
// 	db, err := s.db.DB()
// 	if err != nil {
// 		return err
// 	}
// 	return db.Close()
// }
