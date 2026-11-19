package transport

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	get := func(tr *http.Transport) error {
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	// default: the test server's private CA is untrusted
	tr, err := New("", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if get(tr) == nil {
		t.Error("expected verification failure with no CA configured")
	}

	// --insecure skips verification
	tr, err = New("", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := get(tr); err != nil {
		t.Errorf("insecure: %v", err)
	}

	// --ca-cert trusts the server's CA, with verification still on
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err = New("", false, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(tr); err != nil {
		t.Errorf("caCert: %v", err)
	}
}

func TestNewErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)

	if _, err := New("", false, bad); err == nil {
		t.Error("expected error for invalid PEM")
	}
	if _, err := New("", false, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
	if _, err := New("", true, bad); err == nil {
		t.Error("expected error for --insecure with --ca-cert")
	}
	if _, err := New("proxy.corp:8080", false, ""); err == nil {
		t.Error("expected error for proxy without a scheme")
	}
}

func TestNewResponseHeaderTimeout(t *testing.T) {
	tr, err := New("", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if tr.ResponseHeaderTimeout != ResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, ResponseHeaderTimeout)
	}

	// a server that accepts the request and never answers must not hang the client
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout took %v", time.Since(start))
	}
}
