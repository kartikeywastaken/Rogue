// Package testutil contains only fixtures used by tests, never a runtime backend.
package testutil

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
)

// NewServer preserves real loopback tests on normal machines while reporting an
// explicit skip when a restricted sandbox forbids opening any listening socket.
func NewServer(test *testing.T, handler http.Handler) *httptest.Server {
	test.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			test.Skipf("loopback integration unavailable in this sandbox: %v", err)
		}
		test.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	return server
}

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (transport RoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}
