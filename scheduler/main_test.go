package scheduler

import (
	"log/slog"
	"os"
	"testing"
)

// TestMain silences scheduler logs so test output stays readable.
func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.DiscardHandler))
	os.Exit(m.Run())
}
