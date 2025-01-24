package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/jwtauth"
	"goKeeperYandex/package/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type MockStorager struct {
	mock.Mock
}

func (m *MockStorager) CreateUser(ctx context.Context, user models.User) (int, error) {
	args := m.Called(ctx, user)
	return args.Get(0).(int), args.Error(1)
}

func (m *MockStorager) SaveRefreshToken(ctx context.Context, userRefresh models.RefreshToken) error {
	args := m.Called(ctx, userRefresh)
	return args.Error(0)
}

func (m *MockStorager) CheckMasterPassword(ctx context.Context, userID int) (string, error) {
	args := m.Called(ctx, userID)
	return args.String(0), args.Error(1)
}

func (m *MockStorager) StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error {
	args := m.Called(ctx, userID, masterPasswordHash)
	return args.Error(0)
}

func (m *MockStorager) AuthenticateUser(ctx context.Context, username, password string) (bool, error) {
	args := m.Called(ctx, username, password)
	return args.Bool(0), args.Error(1)
}

func TestRegisterUser(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	user := models.User{
		Username:     "testuser",
		PasswordHash: "password",
	}

	mockStorager.On("CreateUser", mock.Anything, mock.Anything).Return(1, nil)
	mockStorager.On("SaveRefreshToken", mock.Anything, mock.Anything).Return(nil)

	registeredUser, err := service.RegisterUser(context.Background(), user)
	assert.NoError(t, err)
	assert.NotNil(t, registeredUser)
	assert.Equal(t, 1, registeredUser.UserID)
	mockStorager.AssertExpectations(t)
}

func TestMasterPasswordCheckOrStore(t *testing.T) {
	mockStorager := new(MockStorager)
	logger := logger.NewLogger("info")
	jwtService := jwtauth.NewJWTService("secret", "issuer")
	service := &Service{
		stor:       mockStorager,
		jwtService: jwtService,
		logger:     logger,
	}

	token, _ := jwtService.CreateAccessToken(1, time.Minute*60)
	masterPassword := "masterpassword"

	mockStorager.On("CheckMasterPassword", mock.Anything, mock.Anything).Return("", errors.New("record not found"))
	mockStorager.On("StoreMasterPassword", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	result, err := service.MasterPasswordCheckOrStore(context.Background(), token, masterPassword)
	assert.NoError(t, err)
	assert.True(t, result)
	mockStorager.AssertExpectations(t)
}
