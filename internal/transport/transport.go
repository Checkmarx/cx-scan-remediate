// Package transport builds the HTTP transport shared by the Checkmarx One and GitHub clients, so
// that --proxy, --insecure and --ca-cert apply to every outbound call.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ResponseHeaderTimeout bounds the wait for a server's response headers after the request has
// been sent. It does not limit reading the body, so long-lived event streams are unaffected once
// they have started.
const ResponseHeaderTimeout = 120 * time.Second

// New builds the HTTP transport for calls to Checkmarx One. TLS verification stays on unless
// insecure is set; caCertFile adds extra trusted CAs (e.g. a TLS-inspecting proxy's) to the
// system pool.
func New(proxy string, insecure bool, caCertFile string) (*http.Transport, error) {
	if insecure && caCertFile != "" {
		return nil, fmt.Errorf("--insecure and --ca-cert are mutually exclusive")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Go's default transport has no limit on how long a server may take to start responding,
	// so a server that accepts the connection and then stalls would hang the run forever.
	transport.ResponseHeaderTimeout = ResponseHeaderTimeout

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil || proxyURL.Scheme == "" || proxyURL.Host == "" {
			return nil, fmt.Errorf("invalid -proxy %q: expected a URL such as http://host:port", proxy)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	switch {
	case insecure:
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case caCertFile != "":
		// The operator chooses this file (--ca-cert), so it may be anywhere; it is only read.
		pem, err := os.ReadFile(filepath.Clean(caCertFile))
		if err != nil {
			return nil, fmt.Errorf("reading --ca-cert: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-cert %s contains no valid PEM certificates", caCertFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return transport, nil
}
