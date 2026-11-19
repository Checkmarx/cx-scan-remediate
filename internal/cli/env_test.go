package cli

import (
	"testing"
)

func TestValueOrEnv(t *testing.T) {
	t.Setenv("CXSR_TEST_A", " from-env ")
	t.Setenv("CXSR_TEST_B", "second")
	if got := valueOrEnv("flag", "CXSR_TEST_A"); got != "flag" {
		t.Errorf("flag must win, got %q", got)
	}
	if got := valueOrEnv("  ", "CXSR_TEST_A"); got != "from-env" {
		t.Errorf("got %q", got)
	}
	if got := valueOrEnv("", "CXSR_TEST_MISSING", "CXSR_TEST_B"); got != "second" {
		t.Errorf("got %q", got)
	}
	if got := valueOrEnv("", "CXSR_TEST_MISSING"); got != "" {
		t.Errorf("got %q", got)
	}
}
