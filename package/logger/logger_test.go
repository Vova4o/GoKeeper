package logger

import (
    "bytes"
    "log"
    "strings"
    "testing"
)

func TestLogger(t *testing.T) {
    tests := []struct {
        level    LogLevel
        logFunc  func(*Logger, string)
        expected string
    }{
        {INFO, (*Logger).Info, "INFO: test info message"},
        {WARNING, (*Logger).Warning, "WARNING: test warning message"},
        {DEBUG, (*Logger).Debug, "DEBUG: test debug message"},
        {ERROR, (*Logger).Error, "ERROR: test error message"},
    }

    for _, tt := range tests {
        var buf bytes.Buffer
        logger := &Logger{
            logger:   log.New(&buf, "", log.Ldate|log.Ltime),
            logLevel: tt.level,
        }
        tt.logFunc(logger, tt.expected[strings.Index(tt.expected, ":")+2:])
        if !strings.Contains(buf.String(), tt.expected) {
            t.Errorf("expected log message %q, got %q", tt.expected, buf.String())
        }
    }
}

func TestParseLogLevel(t *testing.T) {
    tests := []struct {
        input    string
        expected LogLevel
    }{
        {"info", INFO},
        {"Info", INFO},
        {"INFO", INFO},
        {"warning", WARNING},
        {"Warning", WARNING},
        {"WARNING", WARNING},
        {"debug", DEBUG},
        {"Debug", DEBUG},
        {"DEBUG", DEBUG},
        {"error", ERROR},
        {"Error", ERROR},
        {"ERROR", ERROR},
        {"unknown", INFO}, // default case
    }

    for _, tt := range tests {
        result := ParseLogLevel(tt.input)
        if result != tt.expected {
            t.Errorf("ParseLogLevel(%q) = %v, expected %v", tt.input, result, tt.expected)
        }
    }
}