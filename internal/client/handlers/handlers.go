package handlers

import (
	"context"
	"time"

	"goKeeperYandex/package/logger"
	pb "goKeeperYandex/protobuf/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCClient struct for client
type GRPCClient struct {
	log    *logger.Logger
	conn   *grpc.ClientConn
	client pb.AuthServiceClient
	ctx    context.Context
}

// NewGRPCClient function for creating new client
func NewGRPCClient(ctx context.Context, address string, creds credentials.TransportCredentials) (*GRPCClient, error) {
	conn, err := grpc.DialContext(ctx, address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}

	client := pb.NewAuthServiceClient(conn)
	return &GRPCClient{conn: conn, client: client}, nil
}

// Close function for closing connection
func (c *GRPCClient) Close() {
	c.conn.Close()
}

// Login function for login user in server
func (c *GRPCClient) Login(username, password string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := c.client.Login(ctx, &pb.LoginRequest{Username: username, Password: password})
	if err != nil {
		return "Error login:", err
	}
	return res.Token, nil
}

// Register function for register user in server
func (c *GRPCClient) Register(username, password string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	res, err := c.client.Register(ctx, &pb.RegisterRequest{Username: username, Password: password})
	if err != nil {
		return "Error registring:", err
	}
	return res.Token, nil
}
