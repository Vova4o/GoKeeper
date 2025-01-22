package service

import (
	"context"

	"goKeeperYandex/internal/server/storage"
	pb "goKeeperYandex/protobuf/auth"
)

// Service struct
type Service struct {
	stor *storage.Storage
}

// NewService создает новый экземпляр сервиса
func NewService(stor *storage.Storage) *Service {
	return &Service{stor: stor}
}

// RegisterUser регистрирует нового пользователя
func (s *Service) RegisterUser(ctx context.Context, username, password string) (bool, error) {
	return s.stor.CreateUser(ctx, username, password)
}

// AuthenticateUser аутентифицирует пользователя
func (s *Service) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
	return s.stor.AuthenticateUser(ctx, username, password)
}

// RecordData записывает данные
func (s *Service) RecordData(ctx context.Context, userID string, data *pb.Data) error {
	return s.stor.RecordData(ctx, userID, data)
}

// ReadData читает данные по типу
func (s *Service) ReadData(ctx context.Context, userID string) ([]*pb.Data, error) {
	return s.stor.ReadData(ctx, userID)
}
