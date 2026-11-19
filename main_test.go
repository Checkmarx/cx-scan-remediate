package main

import (
	"testing"
)

func TestExitCodeForIsNeverZero(t *testing.T) {
	if got := exitCodeFor(0); got != exitGateFailed {
		t.Errorf("exitCodeFor(0) = %d, want %d", got, exitGateFailed)
	}
	if got := exitCodeFor(2); got != exitError {
		t.Errorf("exitCodeFor(2) = %d, want %d", got, exitError)
	}
}
