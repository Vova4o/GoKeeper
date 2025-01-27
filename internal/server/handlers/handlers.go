package handlers

import (
	"context"
	"errors"
	"time"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Claims struct for JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// HandleServiceServer struct
type HandleServiceServer struct {
	pb.UnimplementedAuthServiceServer
	jwtService JWTServicer
	serv       Servicer
	jwtKey     []byte
	logger     *logger.Logger
}

// Servicer interface
type Servicer interface {
	RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error)
	MasterPasswordCheckOrStore(ctx context.Context, token, masterPassword string) (bool, error)
	AuthenticateUser(ctx context.Context, username, password string) (*models.UserRegesred, error)
	RefreshToken(ctx context.Context, refreshToken string) (*models.UserRegesred, error)
	RecordData(ctx context.Context, userID string, data models.Data) error
	// ReadData(ctx context.Context, userID string) ([]*pb.Data, error)
}

// JWTServicer interface for JWT service methods
type JWTServicer interface {
	CreateAccessToken(userID int, duration time.Duration) (string, error)
	CreateRefreshToken(userID int, duration time.Duration) (string, error)
	ParseToken(tokenString string) (jwt.MapClaims, error)
}

// NewHandlersService function
func NewHandlersService(jwtService JWTServicer, serv Servicer, log *logger.Logger) *HandleServiceServer {
	return &HandleServiceServer{
		jwtService: jwtService,
		serv:       serv,
		jwtKey:     []byte("my_secret_key"), // TODO: move to config
		logger:     log,
	}
}

// Register method
func (s *HandleServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Логика регистрации пользователя
	user := models.User{
		Username:     req.Username,
		PasswordHash: req.Password,
	}

	userAfterReg, err := s.serv.RegisterUser(ctx, user)
	if err != nil {
		s.logger.Error("Failed to register user: " + err.Error())
		return nil, err
	}

	if userAfterReg.UserID == 0 {
		s.logger.Error("User already exists")
		return nil, status.Errorf(codes.AlreadyExists, "user already exists")
	}

	return &pb.RegisterResponse{
		UserID:       int64(userAfterReg.UserID),
		Token:        userAfterReg.AccessToken,
		RefreshToken: userAfterReg.RefreshToken,
	}, nil
}

// AuthFuncOverride method
func (s *HandleServiceServer) AuthFuncOverride(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if info.FullMethod == "/auth.AuthService/Login" || info.FullMethod == "/auth.AuthService/Register" {
		return handler(ctx, req)
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
	}

	token := md["authorization"]
	if len(token) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "missing token")
	}

	claims := &Claims{}
	tkn, err := jwt.ParseWithClaims(token[0], claims, func(token *jwt.Token) (interface{}, error) {
		return s.jwtKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			return nil, status.Errorf(codes.Unauthenticated, "invalid token signature")
		}
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	if !tkn.Valid {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return handler(ctx, req)
}

// MasterPasswordCheckOrStore method for checking or storing master password hash
func (s *HandleServiceServer) MasterPasswordCheckOrStore(ctx context.Context, req *pb.MasterPasswordRequest) (*pb.MasterPasswordResponse, error) {
	// Logick of storring and checking hash of master password
	s.logger.Info("MasterPasswordCheckOrStore handle called!")

	result, err := s.serv.MasterPasswordCheckOrStore(ctx, req.Token, req.MasterPassword)
	if err != nil {
		s.logger.Error("Failed to check or store master password: " + err.Error())
		return nil, err
	}

	// Idea is to return 401 to client, so that client can ask for master password again

	return &pb.MasterPasswordResponse{
		Success: result,
	}, nil
}

// Login method
func (s *HandleServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	s.logger.Info("Login handle called!")

	userAfterLogin, err := s.serv.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
	}

	return &pb.LoginResponse{Token: userAfterLogin.AccessToken, RefreshToken: userAfterLogin.RefreshToken}, nil
}

// RefreshToken method
func (s *HandleServiceServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	s.logger.Info("RefreshToken handle called!")

	userAfterRefresh, err := s.serv.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if err.Error() == "refresh token expired" {
			s.logger.Error("Refresh token expired: " + err.Error())
			return nil, status.Errorf(codes.Unauthenticated, "refresh token expired")
		}
		s.logger.Error("Failed to refresh token: " + err.Error())
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	return &pb.RefreshTokenResponse{
		Token:        userAfterRefresh.AccessToken,
		RefreshToken: userAfterRefresh.RefreshToken,
	}, nil
}

// SendDataToServer method
func (s *HandleServiceServer) SendDataToServer(ctx context.Context, req *pb.SendDataRequest) (*pb.SendDataResponse, error) {
	s.logger.Info("SendData handle called!")

	claims, err := s.jwtService.ParseToken(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		s.logger.Error("Invalid token claims")
		return nil, status.Errorf(codes.Unauthenticated, "invalid token claims")
	}

	// Перемещаем логику извлечения данных на уровень сервиса
	data, err := extractData(req.Data)
	if err != nil {
		s.logger.Error("Failed to extract data: " + err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "failed to extract data")
	}

	err = s.serv.RecordData(ctx, userID, data)
	if err != nil {
		s.logger.Error("Failed to record data: " + err.Error())
		return nil, status.Errorf(codes.Internal, "failed to record data")
	}

	return &pb.SendDataResponse{Success: true}, nil
}

// // SendDataToServer method
// func (s *HandleServiceServer) SendDataToServer(ctx context.Context, req *pb.SendDataRequest) (*pb.SendDataResponse, error) {
// 	s.logger.Info("SendData handle called!")

// 	claims, err := s.jwtService.ParseToken(req.Token)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		s.logger.Error("Invalid token claims: " + err.Error())
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token claims")
// 	}

// 	// Извлекаем данные из запроса и сохраняем их в структуру Data
// 	var data models.Data
// 	switch req.Data.DataType {
// 	case pb.DataType_LOGIN_PASSWORD:
// 		loginPassword := models.LoginPassword{
// 			Username: req.Data.GetLoginPassword().Login,
// 			Password: req.Data.GetLoginPassword().Password,
// 		}
// 		data = models.NewData(models.DataTypeLOGIN, loginPassword)
// 	case pb.DataType_TEXT_NOTE:
// 		textNote := models.TextNote{
// 			Content: req.Data.GetTextNote().Text,
// 		}
// 		data = models.NewData(models.DataTypeNOTE, textNote)
// 	case pb.DataType_BINARY_DATA:
// 		binaryData := models.BinaryData{
// 			Data:     req.Data.GetBinaryData().Data,
// 		}
// 		data = models.NewData(models.DataTypeBINARY, binaryData)
// 	case pb.DataType_BANK_CARD:
// 		bankCard := models.BankCard{
// 			CardNumber: req.Data.GetBankCard().CardNumber,
// 			ExpiryDate: req.Data.GetBankCard().ExpiryDate,
// 			CVV:        req.Data.GetBankCard().Cvv,
// 		}
// 		data = models.NewData(models.DataTypeCARD, bankCard)
// 	default:
// 		return nil, status.Errorf(codes.InvalidArgument, "unknown data type")
// 	}

// 	err = s.serv.RecordData(ctx, userID, data)
// 	if err != nil {
// 		s.logger.Error("Failed to record data: " + err.Error())
// 		return nil, status.Errorf(codes.Internal, "failed to record data")
// 	}

// 	return &pb.SendDataResponse{Success: true}, nil
// }

// // ReceiveData method
// func (s *HandleServiceServer) ReceiveData(ctx context.Context, req *pb.ReceiveDataRequest) (*pb.ReceiveDataResponse, error) {
// 	log.Println("ReceiveData handle called!")

// 	claims, err := s.jwtService.ParseToken(req.Token)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token claims")
// 	}

// 	data, err := s.serv.ReadData(ctx, userID)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "failed to read data")
// 	}

// 	return &pb.ReceiveDataResponse{Data: data}, nil
// }

// extractData function
func extractData(data *pb.Data) (models.Data, error) {
	switch data.DataType {
	case pb.DataType_LOGIN_PASSWORD:
		return models.NewData(models.DataTypeLoginPassword, data.GetLoginPassword())
	case pb.DataType_TEXT_NOTE:
		return models.NewData(models.DataTypeTextNote, data.GetTextNote())
	case pb.DataType_BINARY_DATA:
		return models.NewData(models.DataTypeBinaryData, data.GetBinaryData())
	case pb.DataType_BANK_CARD:
		return models.NewData(models.DataTypeBankCard, data.GetBankCard())
	default:
		return models.Data{}, errors.New("unsupported data type")
	}
}