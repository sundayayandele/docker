// +build linux

package devicemapper

import "C"

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
)

// dmLogLevel gates what level of libdm's debugging output will be forwarded
// through logrus. libdm uses logging *very* liberally and most people using
// --debug [or Docker] aren't going to be debugging libdm bugs. You can change
// this through --storage-opt="dm.libdm_log_level=X".
var dmLogLevel = LogLevelFatal

// DmLogLevel sets the log level at which libdm logs are sent to logrus. This
// is necessary to avoid spamming people looking at the logs of Docker with
// libdm information.
func DmLogLevel(value int) error {
	// Make sure the value makes sense.
	if value < LogLevelFatal || value > LogLevelDebug {
		return fmt.Errorf("invalid libdm log level: must be in range [%d,%d]", LogLevelFatal, LogLevelDebug)
	}
	dmLogLevel = value
	return nil
}

// Due to the way cgo works this has to be in a separate file, as devmapper.go has
// definitions in the cgo block, which is incompatible with using "//export"

// DevmapperLogCallback exports the devmapper log callback for cgo. Note that
// because we are using callbacks, this function will be called for *every* log
// in libdm (even debug ones because there's no way of setting the verbosity
// level for an external logging callback).
//export DevmapperLogCallback
func DevmapperLogCallback(level C.int, file *C.char, line C.int, dmErrnoOrClass C.int, message *C.char) {
	msg := C.GoString(message)

	// Track what errno libdm saw, because the library only gives us 0 or 1.
	if level < LogLevelDebug {
		if strings.Contains(msg, "busy") {
			dmSawBusy = true
		}

		if strings.Contains(msg, "File exists") {
			dmSawExist = true
		}

		if strings.Contains(msg, "No such device or address") {
			dmSawEnxio = true
		}
	}

	if int(level) <= dmLogLevel {
		// Forward the log to the correct logrus level, if allowed by dmLogLevel.
		logMsg := fmt.Sprintf("libdevmapper(%d): %s:%d (%d) %s", int(level), C.GoString(file), int(line), int(dmErrnoOrClass), msg)
		switch level {
		case LogLevelFatal, LogLevelErr:
			logrus.Error(logMsg)
		case LogLevelWarn:
			logrus.Warn(logMsg)
		case LogLevelNotice, LogLevelInfo:
			logrus.Info(logMsg)
		case LogLevelDebug:
			logrus.Debug(logMsg)
		default:
			// Don't drop any "unknown" levels.
			logrus.Info(logMsg)
		}
	}
}

// registerLogCallback registers our own logging callback function for libdm.
//
// Because libdm only gives us {0,1} error codes we need to parse the logs
// produced by libdm (to set dmSawBusy and so on). Note that by registering a
// callback using DevmapperLogCallback, libdm will no longer output logs to
// stderr so we have to log everything ourselves. None of this handling is
// optional because we depend on log callbacks to parse the logs, and if we
// don't forward the log information we'll be in a lot of trouble when
// debugging things.
func registerLogCallback() {
	LogWithErrnoInit()
}

func init() {
	// Register as early as possible so we don't miss anything.
	registerLogCallback()
}
