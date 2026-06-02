package scanner

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// ActiveScanner coordinates execution of dynamic vulnerability modules.
type ActiveScanner struct {
	db     *storage.DB
	client *http.Client
}

// NewActiveScanner initializes an ActiveScanner with a 5s request timeout and redirect controls.
func NewActiveScanner(db *storage.DB) *ActiveScanner {
	return &ActiveScanner{
		db: db,
		client: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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

// Ensure interface functions compile cleanly
var _ context.Context
