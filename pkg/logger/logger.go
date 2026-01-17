package logger

import (
	"fmt"
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
var outputCallback func(string)

// SetLevel sets the global log level.
func SetLevel(level int) {
	currentLevel = level
}

// SetOutputCallback sets a callback function to receive log messages.
func SetOutputCallback(callback func(string)) {
	outputCallback = callback
}

func logMsg(prefix, format string, v ...interface{}) {
	msg := fmt.Sprintf(prefix+format, v...)
	logger.Print(msg)
	if outputCallback != nil {
		outputCallback(msg)
	}
}

// Debug logs debug messages.
func Debug(format string, v ...interface{}) {
	if currentLevel <= LevelDebug {
		logMsg("[DEBUG] ", format, v...)
	}
}

// Info logs info messages.
func Info(format string, v ...interface{}) {
	if currentLevel <= LevelInfo {
		logMsg("[INFO]  ", format, v...)
	}
}

// Warn logs warning messages.
func Warn(format string, v ...interface{}) {
	if currentLevel <= LevelWarn {
		logMsg("[WARN]  ", format, v...)
	}
}

// Error logs error messages.
func Error(format string, v ...interface{}) {
	if currentLevel <= LevelError {
		logMsg("[ERROR] ", format, v...)
	}
}
