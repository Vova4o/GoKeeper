package storage

import (
	"context"
	"database/sql"
	"testing"

	"goKeeperYandex/package/logger"

	"github.com/DATA-DOG/go-sqlmock"
)

func setupTestDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock database: %v", err)
	}
	return db, mock
}

// func TestCreateUser(t *testing.T) {
// 	db, mock := setupTestDB(t)
// 	defer db.Close()

// 	loggerIn := logger.NewLogger("info")
// 	storage := &Storage{db: db, logger: loggerIn}

// 	user := models.User{
// 		Username:     "testuser",
// 		PasswordHash: "hashedpassword",
// 	}

// 	mock.ExpectQuery(`INSERT INTO users \(username, password_hash\) VALUES \(\$1, \$2\) RETURNING id`).
// 		WithArgs(user.Username, user.PasswordHash).
// 		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(1))

// 	userID, err := storage.CreateUser(context.Background(), user)
// 	if err != nil {
// 		t.Errorf("unexpected error: %v", err)
// 	}

// 	if userID == 0 {
// 		t.Errorf("expected userID to be non-zero")
// 	}

// 	if err := mock.ExpectationsWereMet(); err != nil {
// 		t.Errorf("there were unfulfilled expectations: %v", err)
// 	}
// }

// func TestSaveRefreshToken(t *testing.T) {
// 	db, mock := setupTestDB(t)
// 	defer db.Close()

// 	logger := logger.NewLogger("info")
// 	storage := &Storage{db: db, logger: logger}

// 	token := models.RefreshToken{
// 		UserID:    1,
// 		Token:     "refreshtoken",
// 		IsRevoked: false,
// 	}

// 	mock.ExpectExec(`INSERT INTO refresh_tokens \(user_id, token, is_revoked\) VALUES \(\$1, \$2, \$3\)`).
// 		WithArgs(token.UserID, token.Token, token.IsRevoked).
// 		WillReturnResult(sqlmock.NewResult(1, 1))

// 	err := storage.SaveRefreshToken(context.Background(), token)
// 	if err != nil {
// 		t.Errorf("unexpected error: %v", err)
// 	}

// 	if err := mock.ExpectationsWereMet(); err != nil {
// 		t.Errorf("there were unfulfilled expectations: %v", err)
// 	}
// }

// TODO: fix this test
// func TestAuthenticateUser(t *testing.T) {
// 	db, mock := setupTestDB(t)
// 	defer db.Close()

// 	logger := logger.NewLogger("info")
// 	storage := &Storage{db: db, logger: logger}

// 	username := "testuser"
// 	password := "hashedpassword"

// 	mock.ExpectQuery(`SELECT password_hash FROM users WHERE username = \$1`).
// 		WithArgs(username).
// 		WillReturnRows(sqlmock.NewRows([]string{"password_hash"}).AddRow(password))

// 	isAuthenticated, err := storage.AuthenticateUser(context.Background(), username)
// 	if err != nil {
// 		t.Errorf("unexpected error: %v", err)
// 	}

// 	if !isAuthenticated {
// 		t.Errorf("expected user to be authenticated")
// 	}

// 	if err := mock.ExpectationsWereMet(); err != nil {
// 		t.Errorf("there were unfulfilled expectations: %v", err)
// 	}
// }

func TestCheckMasterPassword(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	logger := logger.NewLogger("info")
	storage := &Storage{db: db, logger: logger}

	userID := 1
	masterPasswordHash := "hashedmasterpassword"

	mock.ExpectQuery(`SELECT master_password_hash FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"master_password_hash"}).AddRow(masterPasswordHash))

	hash, err := storage.CheckMasterPassword(context.Background(), userID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if hash != masterPasswordHash {
		t.Errorf("expected master password hash to be %v, got %v", masterPasswordHash, hash)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %v", err)
	}
}

func TestCheckMasterPasswordNotFound(t *testing.T) {
	db, mock := setupTestDB(t)
	defer db.Close()

	logger := logger.NewLogger("info")
	storage := &Storage{db: db, logger: logger}

	userID := 1

	mock.ExpectQuery(`SELECT master_password_hash FROM users WHERE id = \$1`).
		WithArgs(userID).
		WillReturnError(sql.ErrNoRows)

	hash, err := storage.CheckMasterPassword(context.Background(), userID)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if hash != "" {
		t.Errorf("expected master password hash to be empty, got %v", hash)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %v", err)
	}
}

// func TestStoreMasterPassword(t *testing.T) {
//     db, mock := setupTestDB(t)
//     defer db.Close()

//     logger := logger.NewLogger("info")
//     storage := &Storage{db: db, logger: logger}

//     userID := 1
//     masterPasswordHash := "hashedmasterpassword"

//     mock.ExpectExec(`UPDATE users SET master_password_hash = \$1, updated_at = NOW\(\) WHERE id = \$2`).
//         WithArgs(masterPasswordHash, userID).
//         WillReturnResult(sqlmock.NewResult(1, 1))

//     err := storage.StoreMasterPassword(context.Background(), userID, masterPasswordHash)
//     if err != nil {
//         t.Errorf("unexpected error: %v", err)
//     }

//     if err := mock.ExpectationsWereMet(); err != nil {
//         t.Errorf("there were unfulfilled expectations: %v", err)
//     }
// }
