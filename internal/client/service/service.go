package service

import (
	"context"
	"log"

	"goKeeperYandex/package/logger"
)

// Service struct
type Service struct {
	stor   Storager
	logger *logger.Logger
}

// Storager interface
type Storager interface {
	// AddRecord(ctx context.Context, data models.Data, synchronized bool) error
	// GetRecords(ctx context.Context) ([]models.Record, error)
	AddOrReplaceRefreshToken(ctx context.Context, data string) error
	GetRefreshToken(ctx context.Context) (string, error)
}

// NewService creates new service instance
func NewService(stor Storager, logger *logger.Logger) *Service {
	return &Service{
		stor:   stor,
		logger: logger,
	}
}

// AddOrReplaceRefreshToken adds refresh token to storage
func (s *Service) AddOrReplaceRefreshToken(ctx context.Context, data string) error {
	s.logger.Info("Adding refresh token to storage")

	err := s.stor.AddOrReplaceRefreshToken(ctx, data)
	if err != nil {
		log.Println("Failed to add refresh token:", err)
		return err
	}

	return nil
}

// GetRefreshToken reads refresh tokens from storage
func (s *Service) GetRefreshToken(ctx context.Context) (string, error) {
	s.logger.Info("Reading refresh tokens from storage")

	token, err := s.stor.GetRefreshToken(ctx)
	if err != nil {
		log.Println("Failed to get refresh tokens:", err)
		return "", err
	}

	return token, nil
}

// // AddRecord adds record to storage
// func (s *Service) AddRecord(ctx context.Context, data models.Data, synchronized bool) error {
// 	s.logger.Info("Adding record to storage")

// 	// TODO: add validation for data

// 	err := s.stor.AddRecord(ctx, data, synchronized)
// 	if err != nil {
// 		log.Println("Failed to add record:", err)
// 		return err
// 	}

// 	return nil
// }

// // GetRecords reads records from storage
// func (s *Service) GetRecords(ctx context.Context) ([]models.Record, error) {
// 	s.logger.Info("Reading records from storage")

// 	records, err := s.stor.GetRecords(ctx)
// 	if err != nil {
// 		log.Println("Failed to get records:", err)
// 		return nil, err
// 	}

// 	return records, nil
// }
