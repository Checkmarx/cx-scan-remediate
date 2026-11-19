package main

import (
	"context"
	"io"
	"net/http"
	"strings"
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

type stubTransport struct{ calls int }

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
}

// the GitHub client must use the shared transport, so --proxy / --insecure / --ca-cert apply to it too
func TestNewGithubClientUsesTransport(t *testing.T) {
	stub := &stubTransport{}
	client, err := newGithubClient("token", "", stub)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = client.Repositories.Get(context.Background(), "o", "r")
	if stub.calls == 0 {
		t.Error("GitHub request did not go through the supplied transport")
	}
}
