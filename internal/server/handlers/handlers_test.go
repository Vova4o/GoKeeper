package handlers

import (
	"context"
	"testing"
	"time"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Моки для интерфейсов
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) CreateAccessToken(userID int, duration time.Duration) (string, error) {
	args := m.Called(userID, duration)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) CreateRefreshToken(userID int, duration time.Duration) (string, error) {
	args := m.Called(userID, duration)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ParseToken(tokenString string) (jwt.MapClaims, error) {
	args := m.Called(tokenString)
	if claims, ok := args.Get(0).(jwt.MapClaims); ok {
		return claims, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockJWTService) UserIDFromToken(tokenString string) (int, error) {
	args := m.Called(tokenString)
	return args.Int(0), args.Error(1)
}

type MockService struct {
	mock.Mock
}

func (m *MockService) RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error) {
	args := m.Called(ctx, user)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) MasterPasswordCheckOrStore(ctx context.Context, masterPassword string) (bool, error) {
	args := m.Called(ctx, masterPassword)
	return args.Bool(0), args.Error(1)
}

func (m *MockService) AuthenticateUser(ctx context.Context, username, password string) (*models.UserRegesred, error) {
	args := m.Called(ctx, username, password)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) RefreshToken(ctx context.Context, refreshToken string) (*models.UserRegesred, error) {
	args := m.Called(ctx, refreshToken)
	if res, ok := args.Get(0).(*models.UserRegesred); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockService) RecordData(ctx context.Context, userID int, data models.DataToPass) error {
	args := m.Called(ctx, userID, data)
	return args.Error(0)
}

func (m *MockService) ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.DataToPass, error) {
	args := m.Called(ctx, userID, dataType)
	if res, ok := args.Get(0).([]*models.DataToPass); ok {
		return res, args.Error(1)
	}
	return nil, args.Error(1)
}

func TestRegister(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.RegisterRequest
		mockResponse  *models.UserRegesred
		mockError     error
		expectedResp  *pb.RegisterResponse
		expectedError error
	}{
		{
			name: "successful registration",
			request: &pb.RegisterRequest{
				Username: "testuser",
				Password: "testpass",
			},
			mockResponse: &models.UserRegesred{
				UserID:       1,
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			mockError: nil,
			expectedResp: &pb.RegisterResponse{
				UserID:       1,
				Token:        "access_token",
				RefreshToken: "refresh_token",
			},
			expectedError: nil,
		},
		{
			name: "user already exists",
			request: &pb.RegisterRequest{
				Username: "existinguser",
				Password: "testpass",
			},
			mockResponse:  &models.UserRegesred{},
			mockError:     nil,
			expectedResp:  nil,
			expectedError: status.Error(codes.AlreadyExists, "user already exists"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("RegisterUser", mock.Anything, models.User{
				Username:     tt.request.Username,
				PasswordHash: tt.request.Password,
			}).Return(tt.mockResponse, tt.mockError)

			resp, err := handler.Register(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.LoginRequest
		mockResponse  *models.UserRegesred
		mockError     error
		expectedResp  *pb.LoginResponse
		expectedError error
	}{
		{
			name: "successful login",
			request: &pb.LoginRequest{
				Username: "testuser",
				Password: "testpass",
			},
			mockResponse: &models.UserRegesred{
				UserID:       1,
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
			},
			mockError: nil,
			expectedResp: &pb.LoginResponse{
				Token:        "access_token",
				RefreshToken: "refresh_token",
			},
			expectedError: nil,
		},
		{
			name: "invalid credentials",
			request: &pb.LoginRequest{
				Username: "wronguser",
				Password: "wrongpass",
			},
			mockResponse:  nil,
			mockError:     status.Error(codes.Unauthenticated, "invalid credentials"),
			expectedResp:  nil,
			expectedError: status.Error(codes.Unauthenticated, "invalid credentials"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockJWT := &MockJWTService{}
			mockServ := &MockService{}
			logger := logger.NewLogger("info")

			handler := NewHandlersService(mockJWT, mockServ, logger)

			mockServ.On("AuthenticateUser", mock.Anything, tt.request.Username, tt.request.Password).
				Return(tt.mockResponse, tt.mockError)

			resp, err := handler.Login(context.Background(), tt.request)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResp, resp)
			}

			mockServ.AssertExpectations(t)
		})
	}
}

