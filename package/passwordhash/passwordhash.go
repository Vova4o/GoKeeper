package passwordhash

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword хеширует пароль для безопасного хранения в базе данных
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash проверяет, соответствует ли хеш пароля предоставленному паролю
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
