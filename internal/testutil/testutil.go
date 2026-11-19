// Package testutil holds helpers shared by the tests of several packages.
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// Logger returns a logger that writes nothing.
func Logger() *logrus.Logger {
	l := logrus.New()
	l.SetLevel(logrus.PanicLevel)
	return l
}

// QuietLogger returns a logger at debug level whose output is collected in the returned builder.
func QuietLogger() (*logrus.Logger, *strings.Builder) {
	var out strings.Builder
	l := logrus.New()
	l.SetOutput(&out)
	l.SetLevel(logrus.DebugLevel)
	return l, &out
}

// RequireGit skips the test if git is not installed, and makes git ignore the developer's
// configuration for the rest of the test.
func RequireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// ignore the developer's git config: e.g. core.autocrlf=true makes "git apply" write CRLF
	// into new files, which would make byte-exact assertions machine-dependent
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
}

// WriteFile writes content to the forward-slash path rel under dir, creating directories as needed.
func WriteFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
