package storage

import (
	"context"
	"os"
	"testing"

	"goKeeperYandex/package/logger"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestStorage(t *testing.T) (*Storage, func()) {
	// Используем временный файл для тестовой БД
	tmpDB := "./test_keeper.db"
	log := logger.NewLogger("info")

	storage, err := NewStorage(tmpDB, log)
	require.NoError(t, err)
	require.NotNil(t, storage)

	// Функция очистки
	cleanup := func() {
		storage.db.Close()
		os.Remove(tmpDB)
	}

	return storage, cleanup
}

func TestNewStorage(t *testing.T) {
	tests := []struct {
		name        string
		dbPath      string
		expectError bool
	}{
		{
			name:        "successful creation with custom path",
			dbPath:      "./test_custom.db",
			expectError: false,
		},
		{
			name:        "successful creation with default path",
			dbPath:      "",
			expectError: false,
		},
		{
			name:        "invalid path",
			dbPath:      "/invalid/path/db.db",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := logger.NewLogger("info")
			storage, err := NewStorage(tt.dbPath, log)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, storage)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, storage)
				storage.db.Close()
				os.Remove(tt.dbPath)
				if tt.dbPath == "" {
					os.Remove("keeper.db")
				}
			}
		})
	}
}

func TestRefreshToken(t *testing.T) {
	storage, cleanup := setupTestStorage(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name        string
		token       string
		expectError bool
		operation   string // "add", "replace", "get"
		expected    string
	}{
		{
			name:        "add new token",
			token:       "test_token_1",
			expectError: false,
			operation:   "add",
			expected:    "test_token_1",
		},
		{
			name:        "replace existing token",
			token:       "test_token_2",
			expectError: false,
			operation:   "replace",
			expected:    "test_token_2",
		},
		{
			name:        "get existing token",
			token:       "",
			expectError: false,
			operation:   "get",
			expected:    "test_token_2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			switch tt.operation {
			case "add", "replace":
				err = storage.AddOrReplaceRefreshToken(ctx, tt.token)
			case "get":
				var token string
				token, err = storage.GetRefreshToken(ctx)
				if !tt.expectError {
					assert.Equal(t, tt.expected, token)
				}
			}

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
