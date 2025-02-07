package flags

import (
	"log"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// Settings struct
type Settings struct {
	Host     string
	Port     int
	LogLevel string
	Secret   string
	Issuer   string
	DSN      string
	AccessTokenDurationMinutes int
	RefreshTokenDurationDays int
}

// NewSettings creates a new settings instance
func NewSettings() *Settings {
	return &Settings{}
}

// LoadConfig loads the configuration from environment variables, flags, and default values
func (s *Settings) LoadConfig() {
	// Установка значений по умолчанию
	viper.SetDefault("host", "localhost")
	viper.SetDefault("port", 50051)
	viper.SetDefault("log_level", "info")
	viper.SetDefault("secret", "your-secret-key")
	viper.SetDefault("issuer", "your-issuer")
	viper.SetDefault("dsn", "host=localhost user=postgres password=password dbname=goKeeper sslmode=disable")
	viper.SetDefault("access_token_duration_minutes", 15)
	viper.SetDefault("refresh_token_duration_days", 7)
	// dsn: "host=db user=postgres password=password dbname=goKeeper sslmode=disable"

	// Определение флагов командной строки
	pflag.StringP("host", "H", "", "Server host")
	pflag.IntP("port", "P", 0, "Server port")
	pflag.StringP("log_level", "L", "", "Log level")
	pflag.StringP("secret", "S", "", "JWT secret key")
	pflag.StringP("issuer", "I", "", "JWT issuer")
	pflag.StringP("dsn", "D", "", "Data source name")
	pflag.IntP("access_token_duration_minutes", "A", 0, "Access token duration in minutes")
	pflag.IntP("refresh_token_duration_days", "R", 0, "Refresh token duration in days")

	// Парсинг флагов
	pflag.Parse()

	// Связывание флагов с viper
	err := viper.BindPFlags(pflag.CommandLine)
	if err != nil {
		log.Printf("failed to bind flags: %v", err)
	}
	viper.AutomaticEnv()

	// Загрузка конфигурации
	s.Host = viper.GetString("host")
	s.Port = viper.GetInt("port")
	s.LogLevel = viper.GetString("log_level")
	s.Secret = viper.GetString("secret")
	s.Issuer = viper.GetString("issuer")
	s.DSN = viper.GetString("dsn")
	s.AccessTokenDurationMinutes = viper.GetInt("access_token_duration_minutes")
	s.RefreshTokenDurationDays = viper.GetInt("refresh_token_duration_days")
}

// GetAccessTokenDurationMinutes returns the access token duration in minutes
func (s *Settings) GetAccessTokenDurationMinutes() int {
	return s.AccessTokenDurationMinutes
}

// GetRefreshTokenDurationDays returns the refresh token duration in days
func (s *Settings) GetRefreshTokenDurationDays() int {
	return s.RefreshTokenDurationDays
}

// GetHost returns the server host
func (s *Settings) GetHost() string {
	return s.Host
}

// GetDSN returns the data source name
func (s *Settings) GetDSN() string {
	return s.DSN
}

// GetPort returns the server port
func (s *Settings) GetPort() int {
	return s.Port
}

// GetLogLevel returns the log level
func (s *Settings) GetLogLevel() string {
	return s.LogLevel
}

// GetSecret returns the JWT secret key
func (s *Settings) GetSecret() string {
	return s.Secret
}

// GetIssuer returns the JWT issuer
func (s *Settings) GetIssuer() string {
	return s.Issuer
}
