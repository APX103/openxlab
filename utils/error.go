package utils

import (
	"fmt"
	"os"
)

// http://tldp.org/LDP/abs/html/exitcodes.html
const (
	ExitSuccess = iota
	ExitError
	ExitBadConnection
	ExitInterrupted
	ExitIO
	ExitBadArgs = 128
)

// ExitWithError exits with error
func ExitWithError(code int, err error) {
	_, e := fmt.Fprintln(os.Stderr, "Error:", err)
	if e != nil {
		return
	}
	os.Exit(code)
}

// NormalExit exits normally
func NormalExit(msg string) {
	_, err := fmt.Fprintln(os.Stdout, msg)
	if err != nil {
		return
	}
	os.Exit(ExitSuccess)
}

// ExitWithMsg exits with error message
func ExitWithMsg(code int, msg string) {
	_, err := fmt.Fprintln(os.Stderr, msg)
	if err != nil {
		return
	}
	os.Exit(code)
}
