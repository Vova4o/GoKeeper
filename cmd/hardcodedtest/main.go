package main

import (
	"context"
	"log"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/internal/server/storage"
	"goKeeperYandex/package/logger"
)

func main() {
	ctx := context.Background()

	DSN := "host=localhost user=postgres password=password dbname=goKeeper sslmode=disable"

	logger := logger.NewLogger("info")

	stor, err := storage.NewStorage(ctx, DSN, logger)
	if err != nil {
		logger.Error("failed to create storage: " + err.Error())
	}

	userHashed := models.User{
		Username:     "testuser",
		PasswordHash: "hashedpassword",
	}

	userID, err := stor.CreateUser(ctx, userHashed)
	if err != nil {
		logger.Error("failed to create user: " + err.Error())
	}

	logger.Info("User created successfully")
	log.Println("userID: ", userID)
}
