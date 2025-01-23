package storage

import (
	"context"
	"errors"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Storage struct
type Storage struct {
	db     *gorm.DB
	logger *logger.Logger
}

// NewStorage создает новый экземпляр хранилища
func NewStorage(ctx context.Context, connString string, logger *logger.Logger) (*Storage, error) {
	db, err := gorm.Open(postgres.Open(connString), &gorm.Config{})
	if err != nil {
		logger.Error("Failed to connect to the database: " + err.Error())
		return nil, err
	}

	// Автоматическая миграция схемы
	err = db.AutoMigrate(&models.User{}, &models.PrivateInfo{}, &models.RefreshToken{})
	if err != nil {
		logger.Error("Failed to migrate the schema: " + err.Error())
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

	result := s.db.WithContext(ctx).Create(&user)
	if result.Error != nil {
		s.logger.Error("Failed to create user: " + result.Error.Error())
		return 0, result.Error
	}

	// Возвращаем ID созданного пользователя
	s.logger.Info("User created successfully")
	return user.ID, nil
}

// SaveRefreshToken сохраняет refresh токен
func (s *Storage) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	result := s.db.WithContext(ctx).Create(&token)
	if result.Error != nil {
		s.logger.Error("Failed to save refresh token: " + result.Error.Error())
		return result.Error
	}

	s.logger.Info("Refresh token saved successfully")
	return nil
}

// AuthenticateUser аутентифицирует пользователя
func (s *Storage) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
	var user models.User
	result := s.db.WithContext(ctx).Where("username = ?", username).First(&user)
	if result.Error != nil {
		s.logger.Error("Failed to authenticate user: " + result.Error.Error())
		return false, result.Error
	}

	if user.Password != password {
		return false, nil
	}

	return true, nil
}

// RecordData записывает данные
func (s *Storage) RecordData(ctx context.Context, userID string, data *pb.Data) error {
	privateInfo := models.PrivateInfo{
		UserID:   userID,
		DataType: data.DataType.String(),
	}

	switch v := data.Data.(type) {
	case *pb.Data_LoginPassword:
		privateInfo.Data = v.LoginPassword.String()
	case *pb.Data_TextNote:
		privateInfo.Data = v.TextNote.Text
	case *pb.Data_BinaryData:
		privateInfo.Data = string(v.BinaryData.Data)
	case *pb.Data_BankCard:
		privateInfo.Data = v.BankCard.String()
	default:
		return errors.New("unknown data type")
	}

	result := s.db.WithContext(ctx).Create(&privateInfo)
	if result.Error != nil {
		s.logger.Error("Failed to record data: " + result.Error.Error())
		return result.Error
	}

	s.logger.Info("Data recorded successfully")
	return nil
}

// ReadData читает данные по типу
func (s *Storage) ReadData(ctx context.Context, userID string) ([]*pb.Data, error) {
	var privateInfos []models.PrivateInfo
	result := s.db.WithContext(ctx).Where("user_id = ?", userID).Find(&privateInfos)
	if result.Error != nil {
		s.logger.Error("Failed to read data: " + result.Error.Error())
		return nil, result.Error
	}

	var data []*pb.Data
	for _, info := range privateInfos {
		var d pb.Data
		d.DataType = pb.DataType(pb.DataType_value[info.DataType])
		switch info.DataType {
		case pb.DataType_LOGIN_PASSWORD.String():
			d.Data = &pb.Data_LoginPassword{LoginPassword: &pb.LoginPassword{}}
		case pb.DataType_TEXT_NOTE.String():
			d.Data = &pb.Data_TextNote{TextNote: &pb.TextNote{Text: info.Data}}
		case pb.DataType_BINARY_DATA.String():
			d.Data = &pb.Data_BinaryData{BinaryData: &pb.BinaryData{Data: []byte(info.Data)}}
		case pb.DataType_BANK_CARD.String():
			d.Data = &pb.Data_BankCard{BankCard: &pb.BankCard{}}
		default:
			return nil, errors.New("unknown data type")
		}
		data = append(data, &d)
	}

	s.logger.Info("Data read successfully")
	return data, nil
}

// Close закрывает соединение с базой данных
func (s *Storage) Close(ctx context.Context) error {
	db, err := s.db.DB()
	if err != nil {
		return err
	}
	return db.Close()
}
