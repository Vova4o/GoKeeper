package handlers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"goKeeperYandex/internal/client/models"
	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	jwtpac "github.com/golang-jwt/jwt/v4"
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
	// AddRecord(ctx context.Context, data models.Data, synchronized bool) error
	// GetRecords(ctx context.Context) ([]models.Record, error)
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
	token, _, err := new(jwtpac.Parser).ParseUnverified(c.AccessToken, jwtpac.MapClaims{})
	if err != nil {
		c.log.Error("Error parsing token")
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	// Извлечение утверждений (claims)
	claims, ok := token.Claims.(jwtpac.MapClaims)
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

		md := metadata.New(map[string]string{"authorization": refreshToken})
		ctx = metadata.NewOutgoingContext(ctx, md)

		refreshResp, err := c.client.RefreshToken(ctx, refreshReq)
		if err != nil {
			c.log.Error("Error refreshing token on server")
			return status.Errorf(codes.Unauthenticated, "failed to refresh token: %v", err)
		}

		c.log.Info("Refresh token refreshed successfully: " + refreshResp.Token)

		// Обновляем AccessToken и RefreshToken
		c.AccessToken = refreshResp.Token
		err = c.serv.AddOrReplaceRefreshToken(ctx, refreshResp.RefreshToken)
		if err != nil {
			c.log.Error("Error saving refresh token")
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

	encryptedData, err := encryptData(data, c.MasterPassword)
	if err != nil {
		c.log.Error("Error encrypting data")
		return err
	}

	pbData := convertDataToPBDatas(encryptedData)

	err = c.CheckAndRefreshToken(ctx)
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

		decryptedData, err := decryptData(data, c.MasterPassword)
		if err != nil {
			c.log.Error("Error decrypting data")
			return nil, err
		}

		dataList = append(dataList, decryptedData)
	}

	return dataList, nil
}

// encryptData encrypts data based on its type
func encryptData(data models.Data, key string) (models.DataToPass, error) {
	var encryptedData string
	var err error

	switch v := data.Data.(type) {
	case models.LoginPassword:
		encryptedData, err = Encrypt(fmt.Sprintf("%s|%s|%s", v.Title, v.Login, v.Password), key)
	case models.TextNote:
		encryptedData, err = Encrypt(fmt.Sprintf("%s|%s", v.Title, v.Text), key)
	case models.BinaryData:
		encryptedData, err = Encrypt(fmt.Sprintf("%s|%s", v.Title, base64.StdEncoding.EncodeToString(v.Data)), key)
	case models.BankCard:
		encryptedData, err = Encrypt(fmt.Sprintf("%s|%s|%s|%s", v.Title, v.CardNumber, v.ExpiryDate, v.Cvv), key)
	default:
		return models.DataToPass{}, fmt.Errorf("unsupported data type: %T", v)
	}

	if err != nil {
		return models.DataToPass{}, err
	}

	return models.DataToPass{
		DataType:   data.DataType,
		DataString: encryptedData,
	}, nil
}

// decryptData decrypts data based on its type
func decryptData(data models.DataToPass, key string) (models.Data, error) {
	decryptedData, err := Decrypt(data.DataString, key)
	if err != nil {
		return models.Data{}, err
	}

	var dataContent models.DataContent

	switch data.DataType {
	case models.DataTypeLoginPassword:
		parts := strings.Split(decryptedData, "|")
		if len(parts) == 3 {
			dataContent = models.LoginPassword{
				Title:    parts[0],
				Login:    parts[1],
				Password: parts[2],
			}
		} else {
			return models.Data{}, fmt.Errorf("invalid data format for LoginPassword")
		}
	case models.DataTypeTextNote:
		parts := strings.Split(decryptedData, "|")
		if len(parts) == 2 {
			dataContent = models.TextNote{
				Title: parts[0],
				Text:  parts[1],
			}
		} else {
			return models.Data{}, fmt.Errorf("invalid data format for TextNote")
		}
	case models.DataTypeBinaryData:
		parts := strings.Split(decryptedData, "|")
		if len(parts) == 2 {
			decodedData, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil {
				return models.Data{}, err
			}
			dataContent = models.BinaryData{
				Title: parts[0],
				Data:  decodedData,
			}
		} else {
			return models.Data{}, fmt.Errorf("invalid data format for BinaryData")
		}
	case models.DataTypeBankCard:
		parts := strings.Split(decryptedData, "|")
		if len(parts) == 4 {
			dataContent = models.BankCard{
				Title:      parts[0],
				CardNumber: parts[1],
				ExpiryDate: parts[2],
				Cvv:        parts[3],
			}
		} else {
			return models.Data{}, fmt.Errorf("invalid data format for BankCard")
		}
	default:
		return models.Data{}, fmt.Errorf("unsupported data type: %v", data.DataType)
	}

	return models.Data{
		DataType: data.DataType,
		Data:     dataContent,
	}, nil
}

// Encrypt encrypts data using the given key
func Encrypt(data, key string) (string, error) {
	key = adjustKeySize(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using the given key
func Decrypt(data, key string) (string, error) {
	key = adjustKeySize(key)
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// adjustKeySize adjusts the key size to be 16, 24, or 32 bytes
func adjustKeySize(key string) string {
	switch {
	case len(key) < 16:
		return fmt.Sprintf("%-16s", key)[:16]
	case len(key) < 24:
		return fmt.Sprintf("%-24s", key)[:24]
	case len(key) < 32:
		return fmt.Sprintf("%-32s", key)[:32]
	default:
		return key[:32]
	}
}

func convertDataToPBDatas(d models.DataToPass) *pb.DataToPass {
	return &pb.DataToPass{
		DataType:   pb.DataType(d.DataType),
		StringData: d.DataString,
	}
}

func convertPBToData(pbd *pb.DataToPass) models.DataToPass {
	return models.DataToPass{
		DataType:   models.DataTypes(pbd.DataType),
		DataString: pbd.StringData,
	}
}
