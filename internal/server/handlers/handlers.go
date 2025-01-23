package handlers

import (
	"context"
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

// AuthServiceServer struct
type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	jwtService JWTServicer
	serv       Servicer
	jwtKey     []byte
	logger     *logger.Logger
}

// Servicer interface
type Servicer interface {
	RegisterUser(ctx context.Context, user models.User) (*models.UserRegesred, error)
	// AuthenticateUser(ctx context.Context, username, password string) (bool, error)
	// RecordData(ctx context.Context, userID string, data *pb.Data) error
	// ReadData(ctx context.Context, userID string) ([]*pb.Data, error)
}

// JWTServicer interface for JWT service methods
type JWTServicer interface {
	CreateAccessToken(userID string, duration time.Duration) (string, error)
	CreateRefreshToken(userID string, duration time.Duration) (string, error)
	ParseToken(tokenString string) (jwt.MapClaims, error)
}

// NewHandlersService function
func NewHandlersService(jwtService JWTServicer, serv Servicer, log *logger.Logger) *AuthServiceServer {
	return &AuthServiceServer{
		jwtService: jwtService,
		serv:       serv,
		jwtKey:     []byte("my_secret_key"), // TODO: move to config
		logger:     log,
	}
}

// Register method
func (s *AuthServiceServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Логика регистрации пользователя
	user := models.User{
		Username: req.Username,
		Password: req.Password,
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
		UserID:       userAfterReg.UserID,
		Token:        userAfterReg.AccessToken,
		RefreshToken: userAfterReg.RefreshToken,
	}, nil
}

// AuthFuncOverride method
func (s *AuthServiceServer) AuthFuncOverride(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
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

// // Login method
// func (s *AuthServiceServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
// 	log.Println("Login handle called!")

// 	isUser, err := s.serv.AuthenticateUser(ctx, req.Username, req.Password)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
// 	}

// 	if !isUser {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid credentials")
// 	}

// 	accessToken, err := s.jwtService.CreateAccessToken(req.Username, time.Minute*60)
// 	if err != nil {
// 		return nil, err
// 	}

// 	refreshToken, err := s.jwtService.CreateRefreshToken(req.Username, time.Hour*24*7)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &pb.LoginResponse{Token: accessToken, RefreshToken: refreshToken}, nil
// }

// // RefreshToken method
// func (s *AuthServiceServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
// 	log.Println("RefreshToken handle called!")

// 	claims, err := s.jwtService.ParseToken(req.RefreshToken)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid refresh token")
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token claims")
// 	}

// 	accessToken, err := s.jwtService.CreateAccessToken(userID, time.Minute*60)
// 	if err != nil {
// 		return nil, err
// 	}

// 	refreshToken, err := s.jwtService.CreateRefreshToken(userID, time.Hour*24*7)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return &pb.RefreshTokenResponse{Token: accessToken, RefreshToken: refreshToken}, nil
// }

// // SendData method
// func (s *AuthServiceServer) SendData(ctx context.Context, req *pb.SendDataRequest) (*pb.SendDataResponse, error) {
// 	log.Println("SendData handle called!")

// 	claims, err := s.jwtService.ParseToken(req.Token)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
// 	}

// 	userID, ok := claims["user_id"].(string)
// 	if !ok {
// 		return nil, status.Errorf(codes.Unauthenticated, "invalid token claims")
// 	}

// 	err = s.serv.RecordData(ctx, userID, req.Data)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "failed to record data")
// 	}

// 	return &pb.SendDataResponse{Success: true}, nil
// }

// // ReceiveData method
// func (s *AuthServiceServer) ReceiveData(ctx context.Context, req *pb.ReceiveDataRequest) (*pb.ReceiveDataResponse, error) {
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
