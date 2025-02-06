package handlers

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	"goKeeperYandex/internal/client/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	"github.com/dgrijalva/jwt-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// GRPCClient struct for client
type GRPCClient struct {
	log            *logger.Logger
	conn           *grpc.ClientConn
	client         pb.AuthServiceClient
	ctx            context.Context
	AccessToken    string
	MasterPassword string
	serv           Servicer
}

// Servicer interface
type Servicer interface {
	AddOrReplaceRefreshToken(ctx context.Context, data string) error
	GetRefreshToken(ctx context.Context) (string, error)
	AddRecord(ctx context.Context, data models.Data, synchronized bool) error
	GetRecords(ctx context.Context) ([]models.Record, error)
}

// NewGRPCClient function for creating new client
func NewGRPCClient(ctx context.Context, address string, creds credentials.TransportCredentials, log *logger.Logger, serv Servicer) (*GRPCClient, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(creds))
	// conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	client := pb.NewAuthServiceClient(conn)
	return &GRPCClient{
		conn:   conn,
		client: client,
		log:    log,
		ctx:    ctx,
		serv:   serv,
	}, nil
}

// Close function for closing connection
func (c *GRPCClient) Close() {
	c.conn.Close()
}

// Register function for register user in server
func (c *GRPCClient) Register(ctx context.Context, reg models.RegisterAndLogin) error {
	c.log.Info("Register called!")

	res, err := c.client.Register(ctx, &pb.RegisterRequest{Username: reg.Username, Password: reg.Password})
	if err != nil {
		c.log.Error("Error registring user")
		return err
	}

	if res.Token == "" {
		c.log.Error("Empty token")
		return status.Errorf(codes.Internal, "empty token")
	}

	c.AccessToken = res.Token
	err = c.serv.AddOrReplaceRefreshToken(ctx, res.RefreshToken)
	if err != nil {
		c.log.Error("Error saving refresh token")
		return err
	}

	return nil
}

// Login function for login user in server
func (c *GRPCClient) Login(ctx context.Context, reg models.RegisterAndLogin) error {
	c.log.Info("Login called!")

	res, err := c.client.Login(ctx, &pb.LoginRequest{Username: reg.Username, Password: reg.Password})
	if err != nil {
		c.log.Error("Error login user")
		return err
	}

	if res.Token == "" {
		c.log.Error("Empty token")
		return status.Errorf(codes.Internal, "empty token")
	}

	c.AccessToken = res.Token
	c.log.Info("Access token:" + c.AccessToken)
	err = c.serv.AddOrReplaceRefreshToken(ctx, res.RefreshToken)
	if err != nil {
		c.log.Error("Error saving refresh token")
		return err
	}

	return nil
}

// RefreshToken function for refresh token
func (c *GRPCClient) RefreshToken(ctx context.Context) error {
	c.log.Info("RefreshToken called!")

	refreshToken, err := c.serv.GetRefreshToken(ctx)
	if err != nil {
		c.log.Error("Error getting refresh token")
		return err
	}

	if refreshToken == "" {
		c.log.Error("Empty refresh token")
		return status.Errorf(codes.Internal, "empty refresh token")
	}

	res, err := c.client.RefreshToken(ctx, &pb.RefreshTokenRequest{RefreshToken: refreshToken})
	if err != nil {
		c.log.Error("Error refreshing token")
		return err
	}

	// TODO: save AccessToken and RefreshToken
	c.AccessToken = res.Token

	// Logick for saving Refresh token
	err = c.serv.AddOrReplaceRefreshToken(ctx, res.RefreshToken)
	if err != nil {
		c.log.Error("Error saving refresh token")
		return err
	}

	return nil
}

// CheckAndRefreshToken проверяет срок действия AccessToken и обновляет его при необходимости
func (c *GRPCClient) CheckAndRefreshToken(ctx context.Context) error {
	c.log.Info("CheckAndRefreshToken called!")

	// Парсинг токена без проверки подписи
	token, _, err := new(jwt.Parser).ParseUnverified(c.AccessToken, jwt.MapClaims{})
	if err != nil {
		c.log.Error("Error parsing token")
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	// Извлечение утверждений (claims)
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.log.Error("Invalid token claims")
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	// Проверка времени истечения токена
	exp, ok := claims["exp"].(float64)
	if !ok {
		c.log.Error("Expiration time (exp) not found in token")
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	expirationTime := time.Unix(int64(exp), 0)
	if time.Now().After(expirationTime) {
		c.log.Info("Access token expired, refreshing...")

		// Токен истек, обновляем его
		refreshToken, err := c.serv.GetRefreshToken(ctx)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "failed to get refresh token: %v", err)
		}

		if refreshToken == "" {
			return status.Errorf(codes.Unauthenticated, "refresh token not found")
		}

		refreshReq := &pb.RefreshTokenRequest{
			RefreshToken: refreshToken,
		}

		refreshResp, err := c.client.RefreshToken(ctx, refreshReq)
		if err != nil {
			return status.Errorf(codes.Unauthenticated, "failed to refresh token: %v", err)
		}

		c.log.Info("Refresh token refreshed successfully: " + refreshResp.Token)

		// Обновляем AccessToken и RefreshToken
		c.AccessToken = refreshResp.Token
		err = c.serv.AddOrReplaceRefreshToken(ctx, refreshResp.RefreshToken)
		if err != nil {
			return status.Errorf(codes.Internal, "failed to save refresh token: %v", err)
		}

		c.log.Info("Access token refreshed successfully")
	} else {
		// Токен действителен, продолжаем выполнение
		timeRemaining := time.Until(expirationTime)
		timeString := fmt.Sprintf("Access token is valid. Time remaining: %v", timeRemaining)
		c.log.Info(timeString)
	}

	return nil
}

// MasterPasswordStoreOrCheck function for storing master password
func (c *GRPCClient) MasterPasswordStoreOrCheck(ctx context.Context, masterPassword string) (bool, error) {
	// check if AccessToken is still valid time of validity
	// if not, refresh it
	// if yes, continue

	c.log.Info("MasterPasswordStoreOrCheck called!")

	err := c.CheckAndRefreshToken(ctx)
	if err != nil {
		c.log.Error("Error refreshing token")
		return false, err
	}

	log.Println("AccessToken:", c.AccessToken)

	// Добавление токена в метаданные
	md := metadata.New(map[string]string{"authorization": c.AccessToken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	res, err := c.client.MasterPassword(ctx, &pb.MasterPasswordRequest{MasterPassword: masterPassword})
	if err != nil {
		c.log.Error("Error storing master password in server")
		return false, err
	}

	if res.Success {
		c.MasterPassword = masterPassword
	}

	return res.Success, nil
}

// AddDataToServer function for adding data to server
func (c *GRPCClient) AddDataToServer(ctx context.Context, data models.Data) error {
	c.log.Info("AddDataToServer called!")

	pbData := convertDataToPBDatas(data)

	err := c.CheckAndRefreshToken(ctx)
	if err != nil {
		return err
	}

	// Добавление токена в метаданные
	md := metadata.New(map[string]string{"authorization": c.AccessToken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	res, err := c.client.SendData(ctx, &pb.SendDataRequest{Data: pbData})
	if err != nil {
		c.log.Error("Error sending data to server")
		return err
	}

	if !res.Success {
		c.log.Error("Data not saved")
		return status.Errorf(codes.Internal, "data not saved")
	}

	return nil
}

// GetDataFromServer function for getting data from server
func (c *GRPCClient) GetDataFromServer(ctx context.Context, dataType models.DataTypes) ([]models.Data, error) {
	c.log.Info("GetDataFromServer called!")

	err := c.CheckAndRefreshToken(ctx)
	if err != nil {
		c.log.Error("Error refreshing token")
		return nil, err
	}

	// Добавление токена в метаданные
	md := metadata.New(map[string]string{"authorization": c.AccessToken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	stream, err := c.client.ReceiveData(ctx, &pb.ReceiveDataRequest{DataType: pb.DataType(dataType)})
	if err != nil {
		c.log.Error("Error getting data from server")
		return nil, err
	}

	var dataList []models.Data
	for {
		res, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.log.Error("Error receiving data from stream")
			return nil, err
		}

		data := convertPBToData(res.Data)
		dataList = append(dataList, data)
	}

	return dataList, nil
}

func convertDataToPBDatas(d models.Data) *pb.Data {
	switch d.DataType {
	case models.DataTypeLoginPassword:
		// Приводим d.Data к структуре LoginPassword
		lp, ok := d.Data.(models.LoginPassword)
		if !ok {
			return nil
		}
		return &pb.Data{
			DataType: pb.DataType_LOGIN_PASSWORD,
			Data: &pb.Data_LoginPassword{
				LoginPassword: &pb.LoginPassword{
					Title:    lp.Title,
					Login:    lp.Login,
					Password: lp.Password,
				},
			},
		}

	case models.DataTypeTextNote:
		tn, ok := d.Data.(models.TextNote)
		if !ok {
			return nil
		}
		return &pb.Data{
			DataType: pb.DataType_TEXT_NOTE,
			Data: &pb.Data_TextNote{
				TextNote: &pb.TextNote{
					Title: tn.Title,
					Text:  tn.Text,
				},
			},
		}

	case models.DataTypeBinaryData:
		bd, ok := d.Data.(models.BinaryData)
		if !ok {
			return nil
		}
		return &pb.Data{
			DataType: pb.DataType_BINARY_DATA,
			Data: &pb.Data_BinaryData{
				BinaryData: &pb.BinaryData{
					Title: bd.Title,
					Data:  bd.Data,
				},
			},
		}

	case models.DataTypeBankCard:
		bc, ok := d.Data.(models.BankCard)
		if !ok {
			return nil
		}
		return &pb.Data{
			DataType: pb.DataType_BANK_CARD,
			Data: &pb.Data_BankCard{
				BankCard: &pb.BankCard{
					Title:      bc.Title,
					CardNumber: bc.CardNumber,
					ExpiryDate: bc.ExpiryDate,
					Cvv:        bc.Cvv,
				},
			},
		}
	default:
		return nil
	}
}

func convertPBToData(pbd *pb.Data) models.Data {
	if pbd == nil {
		return models.Data{}
	}

	var result models.Data

	switch pbd.DataType {
	case pb.DataType_LOGIN_PASSWORD:
		lp := pbd.GetLoginPassword()
		if lp == nil {
			return models.Data{}
		}
		result = models.Data{
			DataType: models.DataTypeLoginPassword,
			Data: models.LoginPassword{
				Title:    lp.Title,
				Login:    lp.Login,
				Password: lp.Password,
			},
		}

	case pb.DataType_TEXT_NOTE:
		tn := pbd.GetTextNote()
		if tn == nil {
			return models.Data{}
		}
		result = models.Data{
			DataType: models.DataTypeTextNote,
			Data: models.TextNote{
				Title: tn.Title,
				Text:  tn.Text,
			},
		}

	case pb.DataType_BINARY_DATA:
		bd := pbd.GetBinaryData()
		if bd == nil {
			return models.Data{}
		}
		result = models.Data{
			DataType: models.DataTypeBinaryData,
			Data: models.BinaryData{
				Title: bd.Title,
				Data:  bd.Data,
			},
		}

	case pb.DataType_BANK_CARD:
		bc := pbd.GetBankCard()
		if bc == nil {
			return models.Data{}
		}
		result = models.Data{
			DataType: models.DataTypeBankCard,
			Data: models.BankCard{
				Title:      bc.Title,
				CardNumber: bc.CardNumber,
				ExpiryDate: bc.ExpiryDate,
				Cvv:        bc.Cvv,
			},
		}

	default:
		// Неизвестный тип данных
		return models.Data{}
	}

	return result
}
