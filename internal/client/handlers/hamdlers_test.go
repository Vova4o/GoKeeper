package handlers

import (
	"context"
	"io"
	"testing"
	"time"

	"goKeeperYandex/internal/client/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	jwtpac "github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type MockServicer struct {
	mock.Mock
}

func (m *MockServicer) AddOrReplaceRefreshToken(ctx context.Context, data string) error {
	args := m.Called(ctx, data)
	return args.Error(0)
}

func (m *MockServicer) GetRefreshToken(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func (m *MockServicer) AddRecord(ctx context.Context, data models.Data, synchronized bool) error {
	args := m.Called(ctx, data, synchronized)
	return args.Error(0)
}

func (m *MockServicer) GetRecords(ctx context.Context) ([]models.Record, error) {
	args := m.Called(ctx)
	return args.Get(0).([]models.Record), args.Error(1)
}

type MockAuthServiceClient struct {
	mock.Mock
}

func (m *MockAuthServiceClient) Register(ctx context.Context, in *pb.RegisterRequest, opts ...grpc.CallOption) (*pb.RegisterResponse, error) {
	args := m.Called(ctx, in)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.RegisterResponse), args.Error(1)
}

func (m *MockAuthServiceClient) Login(ctx context.Context, in *pb.LoginRequest, opts ...grpc.CallOption) (*pb.LoginResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*pb.LoginResponse), args.Error(1)
}

func (m *MockAuthServiceClient) RefreshToken(ctx context.Context, in *pb.RefreshTokenRequest, opts ...grpc.CallOption) (*pb.RefreshTokenResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*pb.RefreshTokenResponse), args.Error(1)
}

func (m *MockAuthServiceClient) MasterPassword(ctx context.Context, in *pb.MasterPasswordRequest, opts ...grpc.CallOption) (*pb.MasterPasswordResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*pb.MasterPasswordResponse), args.Error(1)
}

func (m *MockAuthServiceClient) ReceiveData(ctx context.Context, in *pb.ReceiveDataRequest, opts ...grpc.CallOption) (pb.AuthService_ReceiveDataClient, error) {
	args := m.Called(ctx, in)
	// Проверяем первый аргумент на nil
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	// Возвращаем мок стрима и ошибку
	return args.Get(0).(pb.AuthService_ReceiveDataClient), args.Error(1)
}

func (m *MockAuthServiceClient) SendData(ctx context.Context, in *pb.SendDataRequest, opts ...grpc.CallOption) (*pb.SendDataResponse, error) {
	args := m.Called(ctx, in)
	return args.Get(0).(*pb.SendDataResponse), args.Error(1)
}

// Мок для стрима
type MockAuthServiceReceiveDataClient struct {
	mock.Mock
}

func (m *MockAuthServiceReceiveDataClient) Recv() (*pb.ReceiveDataResponse, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*pb.ReceiveDataResponse), args.Error(1)
}

func (m *MockAuthServiceReceiveDataClient) Header() (metadata.MD, error) {
	args := m.Called()
	return args.Get(0).(metadata.MD), args.Error(1)
}

func (m *MockAuthServiceReceiveDataClient) Trailer() metadata.MD {
	args := m.Called()
	return args.Get(0).(metadata.MD)
}

func (m *MockAuthServiceReceiveDataClient) CloseSend() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockAuthServiceReceiveDataClient) Context() context.Context {
	args := m.Called()
	return args.Get(0).(context.Context)
}

func (m *MockAuthServiceReceiveDataClient) SendMsg(msg interface{}) error {
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockAuthServiceReceiveDataClient) RecvMsg(msg interface{}) error {
	args := m.Called(msg)
	return args.Error(0)
}

func setupTestGRPCClient(t *testing.T) (*GRPCClient, *MockServicer, *MockAuthServiceClient, func()) {
	logger := logger.NewLogger("info")
	serv := new(MockServicer)
	authClient := new(MockAuthServiceClient)

	client := &GRPCClient{
		log:    logger,
		client: authClient,
		serv:   serv,
	}

	return client, serv, authClient, func() {}
}

func TestNewGRPCClient(t *testing.T) {
	creds := credentials.NewTLS(nil)
	logger := logger.NewLogger("info")
	serv := &MockServicer{}

	client, err := NewGRPCClient(context.Background(), "localhost:50051", creds, logger, serv)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.NotNil(t, client.conn)
	assert.NotNil(t, client.client)
	assert.Equal(t, logger, client.log)
	assert.Equal(t, serv, client.serv)

	client.Close()
}

func TestRegister(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	tests := []struct {
		name          string
		reg           models.RegisterAndLogin
		mockResponse  *pb.RegisterResponse
		mockError     error
		expectedError error
		wantToken     string
	}{
		{
			name: "successful registration",
			reg: models.RegisterAndLogin{
				Username: "testuser",
				Password: "password",
			},
			mockResponse: &pb.RegisterResponse{
				Token:        "accesstoken",
				RefreshToken: "refreshtoken",
			},
			mockError:     nil,
			expectedError: nil,
			wantToken:     "accesstoken",
		},
		{
			name: "registration error",
			reg: models.RegisterAndLogin{
				Username: "testuser",
				Password: "password",
			},
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "internal error"),
			expectedError: status.Error(codes.Internal, "internal error"),
			wantToken:     "",
		},
		{
			name: "empty token",
			reg: models.RegisterAndLogin{
				Username: "testuser",
				Password: "password",
			},
			mockResponse: &pb.RegisterResponse{
				Token:        "",
				RefreshToken: "refreshtoken",
			},
			mockError:     nil,
			expectedError: status.Error(codes.Internal, "empty token"),
			wantToken:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем состояние клиента перед каждым тестом
			client.AccessToken = ""

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			// Настраиваем моки
			req := &pb.RegisterRequest{
				Username: tt.reg.Username,
				Password: tt.reg.Password,
			}
			authClient.On("Register", mock.Anything, req).Return(tt.mockResponse, tt.mockError)

			if tt.mockResponse != nil && tt.mockResponse.RefreshToken != "" && tt.mockError == nil {
				serv.On("AddOrReplaceRefreshToken", mock.Anything, tt.mockResponse.RefreshToken).Return(nil)
			}

			// Выполняем тест
			err := client.Register(context.Background(), tt.reg)

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantToken, client.AccessToken)

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestLogin(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	tests := []struct {
		name          string
		login         models.RegisterAndLogin
		mockResponse  *pb.LoginResponse
		mockError     error
		expectedError error
		wantToken     string
	}{
		{
			name: "successful login",
			login: models.RegisterAndLogin{
				Username: "testuser",
				Password: "password",
			},
			mockResponse: &pb.LoginResponse{
				Token:        "accesstoken",
				RefreshToken: "refreshtoken",
			},
			mockError:     nil,
			expectedError: nil,
			wantToken:     "accesstoken",
		},
		{
			name: "login error",
			login: models.RegisterAndLogin{
				Username: "testuser",
				Password: "wrong_password",
			},
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "invalid credentials"),
			expectedError: status.Error(codes.Internal, "invalid credentials"),
			wantToken:     "",
		},
		{
			name: "empty token",
			login: models.RegisterAndLogin{
				Username: "testuser",
				Password: "password",
			},
			mockResponse: &pb.LoginResponse{
				Token:        "",
				RefreshToken: "refreshtoken",
			},
			mockError:     nil,
			expectedError: status.Error(codes.Internal, "empty token"),
			wantToken:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем состояние клиента перед каждым тестом
			client.AccessToken = ""

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			// Настраиваем моки
			req := &pb.LoginRequest{
				Username: tt.login.Username,
				Password: tt.login.Password,
			}
			authClient.On("Login", mock.Anything, req).Return(tt.mockResponse, tt.mockError)

			if tt.mockResponse != nil && tt.mockResponse.RefreshToken != "" && tt.mockError == nil {
				serv.On("AddOrReplaceRefreshToken", mock.Anything, tt.mockResponse.RefreshToken).Return(nil)
			}

			// Выполняем тест
			err := client.Login(context.Background(), tt.login)

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantToken, client.AccessToken)

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestRefreshToken(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	tests := []struct {
		name              string
		savedRefreshToken string
		getTokenError     error
		mockResponse      *pb.RefreshTokenResponse
		mockError         error
		expectedError     error
		wantToken         string
	}{
		{
			name:              "successful refresh",
			savedRefreshToken: "old_refresh_token",
			getTokenError:     nil,
			mockResponse: &pb.RefreshTokenResponse{
				Token:        "new_access_token",
				RefreshToken: "new_refresh_token",
			},
			mockError:     nil,
			expectedError: nil,
			wantToken:     "new_access_token",
		},
		{
			name:              "error getting refresh token",
			savedRefreshToken: "",
			getTokenError:     status.Error(codes.Internal, "database error"),
			mockResponse:      nil,
			mockError:         nil,
			expectedError:     status.Error(codes.Internal, "database error"),
			wantToken:         "",
		},
		{
			name:              "empty saved refresh token",
			savedRefreshToken: "",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         nil,
			expectedError:     status.Error(codes.Internal, "empty refresh token"),
			wantToken:         "",
		},
		{
			name:              "refresh token error",
			savedRefreshToken: "old_refresh_token",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         status.Error(codes.Internal, "invalid refresh token"),
			expectedError:     status.Error(codes.Internal, "invalid refresh token"),
			wantToken:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем состояние клиента перед каждым тестом
			client.AccessToken = ""

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			// Настраиваем моки
			serv.On("GetRefreshToken", mock.Anything).Return(tt.savedRefreshToken, tt.getTokenError)

			if tt.savedRefreshToken != "" && tt.getTokenError == nil {
				req := &pb.RefreshTokenRequest{
					RefreshToken: tt.savedRefreshToken,
				}
				authClient.On("RefreshToken", mock.Anything, req).Return(tt.mockResponse, tt.mockError)

				if tt.mockResponse != nil && tt.mockError == nil {
					serv.On("AddOrReplaceRefreshToken", mock.Anything, tt.mockResponse.RefreshToken).Return(nil)
				}
			}

			// Выполняем тест
			err := client.RefreshToken(context.Background())

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantToken, client.AccessToken)

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestCheckAndRefreshToken(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	// Создаем тестовые JWT токены
	validToken := createTestJWT(time.Now().Add(time.Hour))
	expiredToken := createTestJWT(time.Now().Add(-time.Hour))
	invalidToken := "invalid.token.format"

	tests := []struct {
		name              string
		accessToken       string
		savedRefreshToken string
		getTokenError     error
		mockResponse      *pb.RefreshTokenResponse
		mockError         error
		expectedError     error
		wantToken         string
	}{
		{
			name:              "valid token",
			accessToken:       validToken,
			savedRefreshToken: "",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         nil,
			expectedError:     nil,
			wantToken:         validToken,
		},
		{
			name:              "expired token successful refresh",
			accessToken:       expiredToken,
			savedRefreshToken: "old_refresh_token",
			getTokenError:     nil,
			mockResponse: &pb.RefreshTokenResponse{
				Token:        "new_access_token",
				RefreshToken: "new_refresh_token",
			},
			mockError:     nil,
			expectedError: nil,
			wantToken:     "new_access_token",
		},
		{
			name:              "invalid token format",
			accessToken:       invalidToken,
			savedRefreshToken: "",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         nil,
			expectedError:     status.Error(codes.Unauthenticated, "invalid access token"),
			wantToken:         invalidToken,
		},
		{
			name:              "expired token refresh error",
			accessToken:       expiredToken,
			savedRefreshToken: "old_refresh_token",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         status.Error(codes.Unauthenticated, "invalid refresh token"),
			expectedError: status.Errorf(codes.Unauthenticated, "failed to refresh token: %v",
				status.Error(codes.Unauthenticated, "invalid refresh token")),
			wantToken: expiredToken,
		},
		{
			name:              "expired token empty refresh token",
			accessToken:       expiredToken,
			savedRefreshToken: "",
			getTokenError:     nil,
			mockResponse:      nil,
			mockError:         nil,
			expectedError:     status.Error(codes.Unauthenticated, "refresh token not found"),
			wantToken:         expiredToken,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем начальное состояние
			client.AccessToken = tt.accessToken

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			// Настраиваем моки
			if tt.accessToken == expiredToken {
				serv.On("GetRefreshToken", mock.Anything).Return(tt.savedRefreshToken, tt.getTokenError)

				if tt.savedRefreshToken != "" {
					req := &pb.RefreshTokenRequest{
						RefreshToken: tt.savedRefreshToken,
					}
					authClient.On("RefreshToken", mock.Anything, req).Return(tt.mockResponse, tt.mockError)

					if tt.mockResponse != nil && tt.mockError == nil {
						serv.On("AddOrReplaceRefreshToken", mock.Anything, tt.mockResponse.RefreshToken).Return(nil)
					}
				}
			}

			// Выполняем тест
			err := client.CheckAndRefreshToken(context.Background())

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantToken, client.AccessToken)

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestMasterPasswordStoreOrCheck(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	// Создаем валидный токен для тестов
	validToken := createTestJWT(time.Now().Add(time.Hour))

	tests := []struct {
		name           string
		masterPassword string
		accessToken    string
		mockResponse   *pb.MasterPasswordResponse
		mockError      error
		expectedError  error
		wantSuccess    bool
		wantPassword   string
	}{
		{
			name:           "successful store master password",
			masterPassword: "validPassword123",
			accessToken:    validToken,
			mockResponse: &pb.MasterPasswordResponse{
				Success: true,
			},
			mockError:     nil,
			expectedError: nil,
			wantSuccess:   true,
			wantPassword:  "validPassword123",
		},
		{
			name:           "wrong master password",
			masterPassword: "wrongPassword",
			accessToken:    validToken,
			mockResponse: &pb.MasterPasswordResponse{
				Success: false,
			},
			mockError:     nil,
			expectedError: nil,
			wantSuccess:   false,
			wantPassword:  "", // не должен сохраняться при неуспешной проверке
		},
		{
			name:           "server error",
			masterPassword: "testPassword",
			accessToken:    validToken,
			mockResponse:   nil,
			mockError:      status.Error(codes.Internal, "internal server error"),
			expectedError:  status.Error(codes.Internal, "internal server error"),
			wantSuccess:    false,
			wantPassword:   "",
		},
		{
			name:           "invalid token",
			masterPassword: "testPassword",
			accessToken:    "invalid.token",
			mockResponse:   nil,
			mockError:      nil,
			expectedError:  status.Error(codes.Unauthenticated, "invalid access token"),
			wantSuccess:    false,
			wantPassword:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем начальное состояние
			client.AccessToken = tt.accessToken
			client.MasterPassword = ""

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			// Настраиваем моки только если токен валидный
			if tt.accessToken == validToken {
				req := &pb.MasterPasswordRequest{
					MasterPassword: tt.masterPassword,
				}
				authClient.On("MasterPassword", mock.Anything, req).Return(tt.mockResponse, tt.mockError)
			}

			// Выполняем тест
			success, err := client.MasterPasswordStoreOrCheck(context.Background(), tt.masterPassword)

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantSuccess, success)
			assert.Equal(t, tt.wantPassword, client.MasterPassword)

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestAddDataToServer(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	// Создаем валидный токен для тестов
	validToken := createTestJWT(time.Now().Add(time.Hour))

	tests := []struct {
		name          string
		accessToken   string
		masterPass    string
		inputData     models.Data
		mockResponse  *pb.SendDataResponse
		mockError     error
		expectedError error
	}{
		{
			name:        "successful add login password",
			accessToken: validToken,
			masterPass:  "testmaster123",
			inputData: models.Data{
				DataType: models.DataTypeLoginPassword,
				Data: models.LoginPassword{
					Title:    "test title",
					Login:    "test login",
					Password: "test password",
				},
			},
			mockResponse: &pb.SendDataResponse{
				Success: true,
			},
			mockError:     nil,
			expectedError: nil,
		},
		{
			name:        "server error",
			accessToken: validToken,
			masterPass:  "testmaster123",
			inputData: models.Data{
				DataType: models.DataTypeLoginPassword,
				Data: models.LoginPassword{
					Title:    "test title",
					Login:    "test login",
					Password: "test password",
				},
			},
			mockResponse:  nil,
			mockError:     status.Error(codes.Internal, "internal server error"),
			expectedError: status.Error(codes.Internal, "internal server error"),
		},
		{
			name:        "unsuccessful save",
			accessToken: validToken,
			masterPass:  "testmaster123",
			inputData: models.Data{
				DataType: models.DataTypeLoginPassword,
				Data: models.LoginPassword{
					Title:    "test title",
					Login:    "test login",
					Password: "test password",
				},
			},
			mockResponse: &pb.SendDataResponse{
				Success: false,
			},
			mockError:     nil,
			expectedError: status.Error(codes.Internal, "data not saved"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем начальное состояние
			client.AccessToken = tt.accessToken
			client.MasterPassword = tt.masterPass

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil

			if tt.accessToken == validToken {
				authClient.On("SendData", mock.Anything, mock.Anything).Return(tt.mockResponse, tt.mockError)
			}

			// Выполняем тест
			err := client.AddDataToServer(context.Background(), tt.inputData)

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
			}

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
		})
	}
}

func TestGetDataFromServer(t *testing.T) {
	client, serv, authClient, teardown := setupTestGRPCClient(t)
	defer teardown()

	// Создаем валидный токен для тестов
	validToken := createTestJWT(time.Now().Add(time.Hour))

	// Создаем мок для стрима
	mockStream := &MockAuthServiceReceiveDataClient{
		mock.Mock{},
	}

	tests := []struct {
		name          string
		accessToken   string
		masterPass    string
		dataType      models.DataTypes
		setupStream   func()
		expectedData  []models.Data
		expectedError error
	}{
		{
			name:        "successful get login passwords",
			accessToken: validToken,
			masterPass:  "testmaster123",
			dataType:    models.DataTypeLoginPassword,
			setupStream: func() {
				encryptedData, _ := encryptData(models.Data{
					DataType: models.DataTypeLoginPassword,
					Data: models.LoginPassword{
						Title:    "test title",
						Login:    "test login",
						Password: "test password",
					},
				}, "testmaster123")

				pbData := convertDataToPBDatas(encryptedData)
				mockStream.On("Recv").Return(&pb.ReceiveDataResponse{Data: pbData}, nil).Once()
				mockStream.On("Recv").Return(nil, io.EOF)
				authClient.On("ReceiveData", mock.Anything, mock.Anything).Return(mockStream, nil)
			},
			expectedData: []models.Data{
				{
					DataType: models.DataTypeLoginPassword,
					Data: models.LoginPassword{
						Title:    "test title",
						Login:    "test login",
						Password: "test password",
					},
				},
			},
			expectedError: nil,
		},
		{
			name:        "stream error",
			accessToken: validToken,
			masterPass:  "testmaster123",
			dataType:    models.DataTypeLoginPassword,
			setupStream: func() {
				authClient.On("ReceiveData", mock.Anything, mock.Anything).Return(nil,
					status.Error(codes.Internal, "stream error"))
			},
			expectedData:  nil,
			expectedError: status.Error(codes.Internal, "stream error"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Устанавливаем начальное состояние
			client.AccessToken = tt.accessToken
			client.MasterPassword = tt.masterPass

			// Сбрасываем моки
			authClient.ExpectedCalls = nil
			serv.ExpectedCalls = nil
			if mockStream != nil {
				mockStream.ExpectedCalls = nil
			}

			// Настраиваем стрим
			tt.setupStream()

			// Выполняем тест
			data, err := client.GetDataFromServer(context.Background(), tt.dataType)

			// Проверяем результаты
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedError.Error(), err.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedData, data)
			}

			// Проверяем, что все ожидаемые вызовы были выполнены
			authClient.AssertExpectations(t)
			serv.AssertExpectations(t)
			if mockStream != nil {
				mockStream.AssertExpectations(t)
			}
		})
	}
}

func createTestJWT(expirationTime time.Time) string {
	claims := jwtpac.MapClaims{
		"exp": float64(expirationTime.Unix()),
	}
	token := jwtpac.NewWithClaims(jwtpac.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte("test_secret"))
	return tokenString
}
