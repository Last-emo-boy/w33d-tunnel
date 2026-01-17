package logger

import (
	"log"
	"os"
)

// Log Levels
const (
	LevelDebug = 0
	LevelInfo  = 1
	LevelWarn  = 2
	LevelError = 3
)

var currentLevel = LevelInfo
var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

// SetLevel sets the global log level.
func SetLevel(level int) {
	currentLevel = level
}

// Debug logs debug messages.
func Debug(format string, v ...interface{}) {
	if currentLevel <= LevelDebug {
		logger.Printf("[DEBUG] "+format, v...)
	}
}

// Info logs info messages.
func Info(format string, v ...interface{}) {
	if currentLevel <= LevelInfo {
		logger.Printf("[INFO]  "+format, v...)
	}
}

// Warn logs warning messages.
func Warn(format string, v ...interface{}) {
	if currentLevel <= LevelWarn {
		logger.Printf("[WARN]  "+format, v...)
	}
}

// Error logs error messages.
func Error(format string, v ...interface{}) {
	if currentLevel <= LevelError {
		logger.Printf("[ERROR] "+format, v...)
	}
}
