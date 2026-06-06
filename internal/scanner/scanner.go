package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// ActiveScanner coordinates execution of dynamic vulnerability modules.
type ActiveScanner struct {
	db     *storage.DB
	client *http.Client
}

type proxyRoundTripper struct {
	scanID string
	base   http.RoundTripper
}

func (p *proxyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-LastResort-Scan-ID", p.scanID)
	req.Header.Set("User-Agent", "LastResort-ActiveScanner/0.1.0")
	return p.base.RoundTrip(req)
}

// NewActiveScanner initializes an ActiveScanner with a 5s request timeout and proxy routing.
func NewActiveScanner(db *storage.DB, scanID string, proxyPort int) *ActiveScanner {
	var transport http.RoundTripper = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyPort > 0 {
		proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort))
		transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return &ActiveScanner{
		db: db,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &proxyRoundTripper{
				scanID: scanID,
				base:   transport,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (as *ActiveScanner) GetHTTPClient() *http.Client {
	return as.client
}

// AttackSurface represents the request parameter details for injection testing.
type AttackSurface struct {
	URL         string
	Method      string
	BaseBody    []byte
	ContentType string
	Point       InsertionPoint
	IsForm      bool
	FormSel     string
	FormPageURL string
}

// Ensure interface functions compile cleanly
var _ context.Context
