package storage

import (
	"context"
	"database/sql"
	"time"

	"goKeeperYandex/internal/server/models"
	"goKeeperYandex/package/logger"

	// Используем драйвер для PostgreSQL
	_ "github.com/lib/pq"
)

// Storage struct
type Storage struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewStorage создает новый экземпляр хранилища
func NewStorage(ctx context.Context, connString string, logger *logger.Logger) (*Storage, error) {
	db, err := sql.Open("postgres", connString)
	if err != nil {
		return nil, err
	}

	// Проверка соединения
	if err := db.PingContext(ctx); err != nil {
		logger.Error("Failed to connect to the database")
		return nil, err
	}

	logger.Info("Connected to the database")
	return &Storage{
		db:     db,
		logger: logger,
	}, nil
}

// CreateUser создает нового пользователя
func (s *Storage) CreateUser(ctx context.Context, user models.User) (int, error) {
	query := `INSERT INTO users (username, password_hash, created_at, updated_at) VALUES ($1, $2, $3, $4) RETURNING id`
	var userID int
	now := time.Now()
	err := s.db.QueryRowContext(ctx, query, user.Username, user.PasswordHash, now, now).Scan(&userID)
	if err != nil {
		s.logger.Error("Failed to create user")
		return 0, err
	}

	s.logger.Info("User created successfully")
	return userID, nil
}

// SaveRefreshToken сохраняет refresh токен
func (s *Storage) SaveRefreshToken(ctx context.Context, token models.RefreshToken) error {
	query := `INSERT INTO refresh_tokens (user_id, token, is_revoked, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, token.UserID, token.Token, token.IsRevoked, now, now)
	if err != nil {
		s.logger.Error("Failed to save refresh token")
		return err
	}

	s.logger.Info("Refresh token saved successfully")
	return nil
}

// DeleteRefreshToken удаляет refresh токен
func (s *Storage) DeleteRefreshToken(ctx context.Context, token string) error {
	query := `DELETE FROM refresh_tokens WHERE token = $1`
	_, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		s.logger.Error("Failed to delete refresh token")
		return err
	}

	s.logger.Info("Refresh token deleted successfully")
	return nil
}

// GetRefreshTokens возвращает все refresh токены пользователя по его ID из базы данных
func (s *Storage) GetRefreshTokens(ctx context.Context, userID int) ([]models.RefreshToken, error) {
	query := `SELECT token, is_revoked FROM refresh_tokens WHERE user_id = $1`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		s.logger.Error("Failed to get refresh tokens")
		return nil, err
	}
	defer rows.Close()

	var tokens []models.RefreshToken
	for rows.Next() {
		var token models.RefreshToken
		if err := rows.Scan(&token.Token, &token.IsRevoked); err != nil {
			s.logger.Error("Failed to scan refresh token")
			return nil, err
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		s.logger.Error("Failed to iterate over refresh tokens")
		return nil, err
	}

	return tokens, nil
}

// FindUserByName ищет пользователя
func (s *Storage) FindUserByName(ctx context.Context, username string) (*models.User, error) {
	query := `SELECT id, password_hash FROM users WHERE username = $1`
	user := &models.User{}
	err := s.db.QueryRowContext(ctx, query, username).Scan(&user.UserID, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		s.logger.Error("Failed to find user")
		return nil, err
	}

	return user, nil
}

// FindUserByID ищет пользователя по ID
func (s *Storage) FindUserByID(ctx context.Context, userID int) (*models.User, error) {
	query := `SELECT id, username, password_hash FROM users WHERE id = $1`
	user := &models.User{}
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&user.UserID, &user.Username, &user.PasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		s.logger.Error("Failed to find user by ID")
		return nil, err
	}

	return user, nil
}

// SaveLoginPassword сохраняет логин и пароль
func (s *Storage) SaveLoginPassword(ctx context.Context, userID int, loginPassword models.LoginPassword) error {
	query := `UPDATE private_infos SET username = $1, password = $2, updated_at = $3 WHERE user_id = $4 AND data_type = $5`
	_, err := s.db.ExecContext(ctx, query, loginPassword.Login, loginPassword.Password, time.Now(), userID, models.DataTypeLoginPassword)
	if err != nil {
		s.logger.Error("Failed to save login password")
		return err
	}

	s.logger.Info("Login password saved successfully")
	return nil
}

// CheckMasterPassword проверяет мастер-пароль
func (s *Storage) CheckMasterPassword(ctx context.Context, userID int) (string, error) {
	query := `SELECT master_password_hash FROM users WHERE id = $1`
	var masterPasswordHash sql.NullString
	err := s.db.QueryRowContext(ctx, query, userID).Scan(&masterPasswordHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		s.logger.Error("Failed to check master password")
		return "", err
	}

	if !masterPasswordHash.Valid {
		return "", nil
	}

	return masterPasswordHash.String, nil
}

// StoreMasterPassword сохраняет мастер-пароль
func (s *Storage) StoreMasterPassword(ctx context.Context, userID int, masterPasswordHash string) error {
	query := `UPDATE users SET master_password_hash = $1, updated_at = $2 WHERE id = $3`
	_, err := s.db.ExecContext(ctx, query, masterPasswordHash, time.Now(), userID)
	if err != nil {
		s.logger.Error("Failed to store master password")
		return err
	}

	s.logger.Info("Master password stored successfully")
	return nil
}

// SaveData сохраняет данные в базу данных в зависимости от типа
func (s *Storage) SaveData(ctx context.Context, userID int, dataType models.DataType, data string) error {
	s.logger.Info("Saving data to DB called")

	query := `INSERT INTO private_infos (user_id, data_type, data, created_at, updated_at) VALUES ($1, $2, $3, $4, $5)`
	now := time.Now()
	_, err := s.db.ExecContext(ctx, query, userID, dataType, data, now, now)
	if err != nil {
		s.logger.Error("Failed to save data")
		return err
	}

	s.logger.Info("Data saved successfully")
	return nil
}

// ReadData читает данные по типу
func (s *Storage) ReadData(ctx context.Context, userID int, dataType models.DataType) ([]*models.PrivateInfo, error) {
	query := `SELECT user_id, data_type, data FROM private_infos WHERE user_id  = $1 AND data_type = $2`
	rows, err := s.db.QueryContext(ctx, query, userID, dataType)
	if err != nil {
		s.logger.Error("Failed to read data: " + err.Error())
		return nil, err
	}
	defer rows.Close()

	var dataList []*models.PrivateInfo
	for rows.Next() {
		var privateInfo models.PrivateInfo

		err := rows.Scan(&privateInfo.UserID, &privateInfo.DataType, &privateInfo.Data)
		if err != nil {
			s.logger.Error("Failed to scan row: " + err.Error())
			return nil, err
		}

		dataList = append(dataList, &privateInfo)
	}

	if err := rows.Err(); err != nil {
		s.logger.Error("Rows error: " + err.Error())
		return nil, err
	}

	s.logger.Info("Data read successfully")
	return dataList, nil
}

// Close закрывает соединение с базой данных
func (s *Storage) Close(ctx context.Context) error {
	return s.db.Close()
}
