package main

import (
	"fmt"
	"io"
	"os"
)

// openLogOutput resolves logging.output: "stdout" (default), "stderr" or an
// absolute file path. Files are opened in append mode so external rotation
// with copytruncate keeps working without reopening. The returned close
// function is always safe to call.
func openLogOutput(output string) (io.Writer, func(), error) {
	switch output {
	case "", "stdout":
		return os.Stdout, func() {}, nil
	case "stderr":
		return os.Stderr, func() {}, nil
	}
	f, err := os.OpenFile(output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return os.Stdout, func() {}, fmt.Errorf("opening log file %s: %w", output, err)
	}
	return f, func() { _ = f.Close() }, nil
}
