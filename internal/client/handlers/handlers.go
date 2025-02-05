package handlers

import (
	"context"
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

	// Проверка срока действия AccessToken
	token, err := jwt.Parse(c.AccessToken, nil)
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "invalid access token")
	}

	if exp > float64(time.Now().Unix()) {
		// Токен действителен, продолжаем выполнение
		return nil
	}

	// Токен истек, обновляем его
	c.log.Info("Access token expired, refreshing...")

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

	c.log.Info("Refresh token refreshed successfully:" + refreshResp.Token)

	// Обновляем AccessToken и RefreshToken
	c.AccessToken = refreshResp.Token
	c.serv.AddOrReplaceRefreshToken(ctx, refreshResp.RefreshToken)

	c.log.Info("Access token refreshed successfully")
	return nil
}

// MasterPasswordStoreOrCheck function for storing master password
func (c *GRPCClient) MasterPasswordStoreOrCheck(ctx context.Context, masterPassword string) (bool, error) {
	// check if AccessToken is still valid time of validity
	// if not, refresh it
	// if yes, continue

	c.log.Info("MasterPasswordStoreOrCheck called!")

	c.CheckAndRefreshToken(ctx)

	// Добавление токена в метаданные
	md := metadata.New(map[string]string{"authorization": c.AccessToken})
	ctx = metadata.NewOutgoingContext(ctx, md)

	res, err := c.client.MasterPassword(ctx, &pb.MasterPasswordRequest{MasterPassword: masterPassword})
	if err != nil {
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

	c.CheckAndRefreshToken(ctx)

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

// // GetDataFromServer function for getting data from server
// func (c *GRPCClient) GetDataFromServer(ctx context.Context, dataType models.DataTypes) ([]models.Data, error) {
// 	c.log.Info("GetDataFromServer called!")

// 	c.CheckAndRefreshToken(ctx)

// 	// Добавление токена в метаданные
// 	md := metadata.New(map[string]string{"authorization": c.AccessToken})
// 	ctx = metadata.NewOutgoingContext(ctx, md)

// 	res, err := c.client.ReceiveData(ctx, &pb.GetRequest{DataType: pb.DataType(dataType)})
// 	if err != nil {
// 		c.log.Error("Error getting data from server")
// 		return nil, err
// 	}

// 	return convertPBToData(res.Data), nil
// }

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
