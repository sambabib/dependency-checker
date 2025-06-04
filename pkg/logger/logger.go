package logger

import (
	"fmt"
	"log"
	"os"
	"time"
)

var (
	verboseMode bool
	infoLogger  *log.Logger
	debugLogger *log.Logger
	errorLogger *log.Logger
)

func init() {
	// Initialize loggers to os.Stdout and os.Stderr
	// Timestamps will be added by the Logf functions if verbose
	infoLogger = log.New(os.Stdout, "", 0) // No prefix or flags for standard info
	debugLogger = log.New(os.Stdout, "", 0) // Debug will get timestamp prefix
	errorLogger = log.New(os.Stderr, "ERROR: ", 0) // Error prefix
}

// SetVerbose enables or disables verbose logging.
func SetVerbose(verbose bool) {
	verboseMode = verbose
}

// IsVerbose returns true if verbose mode is enabled.
func IsVerbose() bool {
	return verboseMode
}

func getTimestamp() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Debugf logs a formatted debug message if verbose mode is enabled.
// Includes a timestamp.
func Debugf(format string, v ...interface{}) {
	if verboseMode {
		debugLogger.Printf("[%s] DEBUG: %s", getTimestamp(), fmt.Sprintf(format, v...))
	}
}

// Infof logs a formatted informational message.
func Infof(format string, v ...interface{}) {
	infoLogger.Printf(format, v...)
}

// Errorf logs a formatted error message.
func Errorf(format string, v ...interface{}) {
	errorLogger.Printf(format, v...)
}
