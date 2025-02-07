package flags

import (
	"os"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestSettings(t *testing.T) {
	// Сохраняем оригинальные значения окружения
	originalEnv := make(map[string]string)
	envVars := []string{
		"HOST", "PORT", "LOG_LEVEL", "SECRET", "ISSUER", "DSN",
		"ACCESS_TOKEN_DURATION_MINUTES", "REFRESH_TOKEN_DURATION_DAYS",
	}
	for _, env := range envVars {
		if value, exists := os.LookupEnv(env); exists {
			originalEnv[env] = value
		}
	}

	// Очищаем переменные окружения после теста
	defer func() {
		for _, env := range envVars {
			if value, exists := originalEnv[env]; exists {
				os.Setenv(env, value)
			} else {
				os.Unsetenv(env)
			}
		}
	}()

	// Очищаем все флаги перед тестами
	pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
	viper.Reset()

	tests := []struct {
		name     string
		envVars  map[string]string
		expected Settings
	}{
		// ... существующие тест-кейсы ...
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Очищаем флаги и Viper перед каждым тестом
			pflag.CommandLine = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
			viper.Reset()

			// Устанавливаем тестовые переменные окружения
			for key, value := range tt.envVars {
				os.Setenv(key, value)
			}

			settings := NewSettings()
			settings.LoadConfig()

			// Проверяем все поля структуры Settings
			assert.Equal(t, tt.expected.Host, settings.GetHost())
			assert.Equal(t, tt.expected.Port, settings.GetPort())
			assert.Equal(t, tt.expected.LogLevel, settings.GetLogLevel())
			assert.Equal(t, tt.expected.Secret, settings.GetSecret())
			assert.Equal(t, tt.expected.Issuer, settings.GetIssuer())
			assert.Equal(t, tt.expected.DSN, settings.GetDSN())
			assert.Equal(t, tt.expected.AccessTokenDurationMinutes, settings.GetAccessTokenDurationMinutes())
			assert.Equal(t, tt.expected.RefreshTokenDurationDays, settings.GetRefreshTokenDurationDays())

			// Очищаем тестовые переменные окружения
			for key := range tt.envVars {
				os.Unsetenv(key)
			}
		})
	}
}

func TestGetters(t *testing.T) {
	settings := &Settings{
		Host:                       "testhost",
		Port:                       8080,
		LogLevel:                   "debug",
		Secret:                     "testsecret",
		Issuer:                     "testissuer",
		DSN:                        "testdsn",
		AccessTokenDurationMinutes: 30,
		RefreshTokenDurationDays:   14,
	}

	tests := []struct {
		name     string
		getter   func() interface{}
		expected interface{}
	}{
		{
			name:     "GetHost",
			getter:   func() interface{} { return settings.GetHost() },
			expected: "testhost",
		},
		{
			name:     "GetPort",
			getter:   func() interface{} { return settings.GetPort() },
			expected: 8080,
		},
		{
			name:     "GetLogLevel",
			getter:   func() interface{} { return settings.GetLogLevel() },
			expected: "debug",
		},
		{
			name:     "GetSecret",
			getter:   func() interface{} { return settings.GetSecret() },
			expected: "testsecret",
		},
		{
			name:     "GetIssuer",
			getter:   func() interface{} { return settings.GetIssuer() },
			expected: "testissuer",
		},
		{
			name:     "GetDSN",
			getter:   func() interface{} { return settings.GetDSN() },
			expected: "testdsn",
		},
		{
			name:     "GetAccessTokenDurationMinutes",
			getter:   func() interface{} { return settings.GetAccessTokenDurationMinutes() },
			expected: 30,
		},
		{
			name:     "GetRefreshTokenDurationDays",
			getter:   func() interface{} { return settings.GetRefreshTokenDurationDays() },
			expected: 14,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.getter())
		})
	}
}
