package ghpr

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

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
