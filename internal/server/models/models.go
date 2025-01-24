package models

import (
	"gorm.io/gorm"
)

// User модель пользователя
type User struct {
	gorm.Model
	Username      string `gorm:"uniqueIndex;not null"`
	PasswordHash      string `gorm:"not null"`
    MasterPasswordHash string `gorm:"default:null"`
	RefreshTokens []RefreshToken
}

// UserRegesred struct to return user tokens after regestration
type UserRegesred struct {
	UserID       uint64
	AccessToken  string
	RefreshToken string
}

// Settings struct
type Settings struct {
	Host     string
	Port     int
	LogLevel string
	Secret   string
	Issuer   string
	DSN      string
}

// RefreshToken модель для хранения refresh токенов
type RefreshToken struct {
	gorm.Model
	UserID    uint64   `gorm:"not null"`
	Token     string `gorm:"not null"`
	IsRevoked bool   `gorm:"not null, default:false"`
}

// PrivateInfo модель для хранения приватной информации
type PrivateInfo struct {
	gorm.Model
	UserID   string `gorm:"not null"`
	DataType string `gorm:"not null"`
	Data     string `gorm:"not null"`
}
