package models

import (
    "gorm.io/gorm"
)

// User модель пользователя
type User struct {
    gorm.Model
    Username string `gorm:"uniqueIndex;not null"`
    Password string `gorm:"not null"`
}

// PrivateInfo модель для хранения приватной информации
type PrivateInfo struct {
    gorm.Model
    UserID   string `gorm:"not null"`
    DataType string `gorm:"not null"`
    Data     string `gorm:"not null"`
}
