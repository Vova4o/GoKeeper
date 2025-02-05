package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"goKeeperYandex/internal/client/handlers"
	"goKeeperYandex/internal/client/service"
	"goKeeperYandex/internal/client/storage"
	"goKeeperYandex/internal/client/ui"
	"goKeeperYandex/package/logger"

	"google.golang.org/grpc/credentials"
)

func main() {
	dbName := "keeper.db"

	// Log message
	logger := logger.NewLogger("info")
	logger.Info("Welcome to the client!")

	stor, err := storage.NewStorage(dbName,logger)
	if err != nil {
		log.Fatalf("Failed to create storage: %v", err)
	}

	serv := service.NewService(stor, logger)

	// Загрузка сертификата с сервера
	resp, err := http.Get("http://localhost:8080/cert")
	if err != nil {
		log.Fatalf("Failed to get certificate: %v", err)
	}
	defer resp.Body.Close()

	certData, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read certificate: %v", err)
	}

	// Создание пула сертификатов
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(certData) {
		log.Fatalf("Failed to append certificate")
	}

	// Настройка TLS
	creds := credentials.NewTLS(&tls.Config{
		RootCAs: certPool,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create new gRPC client for connection to server
	grpcClient, err := handlers.NewGRPCClient(ctx, "localhost:50051", creds, logger, serv)
	if err != nil {
		log.Fatalf("Failed to create gRPC client: %v", err)
	}

	// Create new UI instance
	ui := ui.NewUI(ctx, grpcClient, logger)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Graceful shutdown
	go func() {
		// Wait for the signal
		<-sigChan
		logger.Info("Shutting down the client...")

		// Close the gRPC connection
		grpcClient.Close()

		time.Sleep(5 * time.Second)

		logger.Info("Client is shut down")
		os.Exit(0)
	}()

	ui.RunUI()
}
