package flags

import (
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
	// dsn: "host=db user=postgres password=password dbname=goKeeper sslmode=disable"

	// Определение флагов командной строки
	pflag.StringP("host", "H", "", "Server host")
	pflag.IntP("port", "P", 0, "Server port")
	pflag.StringP("log_level", "L", "", "Log level")
	pflag.StringP("secret", "S", "", "JWT secret key")
	pflag.StringP("issuer", "I", "", "JWT issuer")
	pflag.StringP("dsn", "D", "", "Data source name")

	// Парсинг флагов
	pflag.Parse()

	// Связывание флагов с viper
	viper.BindPFlags(pflag.CommandLine)
	viper.AutomaticEnv()

	// Загрузка конфигурации
	s.Host = viper.GetString("host")
	s.Port = viper.GetInt("port")
	s.LogLevel = viper.GetString("log_level")
	s.Secret = viper.GetString("secret")
	s.Issuer = viper.GetString("issuer")
	s.DSN = viper.GetString("dsn")
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
