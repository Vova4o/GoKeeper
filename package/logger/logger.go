package logger

import (
	"log"
	"os"
)

// LogLevel type
type LogLevel int

// Log levels
const (
	INFO LogLevel = iota
	WARNING
	DEBUG
	ERROR
)

// ParseLogLevel parses a string into a LogLevel
func ParseLogLevel(level string) LogLevel {
	switch level {
	case "info", "Info", "INFO":
		return INFO
	case "warning", "Warning", "WARNING":
		return WARNING
	case "debug", "Debug", "DEBUG":
		return DEBUG
	case "error", "Error", "ERROR":
		return ERROR
	default:
		return INFO
	}
}

// Logger struct
type Logger struct {
	logger   *log.Logger
	logLevel LogLevel
}

// NewLogger creates a new logger instance
func NewLogger(level string) *Logger {
	logLevel := ParseLogLevel(level)
	return &Logger{
		logger:   log.New(os.Stdout, "", log.Ldate|log.Ltime),
		logLevel: logLevel,
	}
}

// Info logs an info message
func (l *Logger) Info(msg string) {
	if l.logLevel <= INFO {
		l.logger.Println("INFO: " + msg)
	}
}

// Warning logs a warning message
func (l *Logger) Warning(msg string) {
	if l.logLevel <= WARNING {
		l.logger.Println("WARNING: " + msg)
	}
}

// Debug logs a debug message
func (l *Logger) Debug(msg string) {
	if l.logLevel <= DEBUG {
		l.logger.Println("DEBUG: " + msg)
	}
}

// Error logs an error message
func (l *Logger) Error(msg string) {
	if l.logLevel <= ERROR {
		l.logger.Println("ERROR: " + msg)
	}
}
