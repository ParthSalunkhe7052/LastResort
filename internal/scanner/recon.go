package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ReconData houses gathered target configuration information
type ReconData struct {
	Headers     map[string]string `json:"headers"`
	Cookies     []string          `json:"cookies"`
	OpenPorts   []int             `json:"open_ports"`
	RobotsPaths []string          `json:"robots_paths"`
}

// RunRecon executes passive-active profiling against the target URL
func RunRecon(ctx context.Context, targetURL string) (*ReconData, error) {
	data := &ReconData{
		Headers: make(map[string]string),
	}

	// 1. Fetch Root URL to extract response headers and cookies
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err == nil {
		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			for k, v := range resp.Header {
				if len(v) > 0 {
					data.Headers[k] = v[0]
				}
			}
			for _, c := range resp.Cookies() {
				data.Cookies = append(data.Cookies, c.Name)
			}
		}
	}

	// 2. Perform raw TCP connection dials to check common web ports
	parsed, err := url.Parse(targetURL)
	if err == nil {
		host := parsed.Hostname()
		commonPorts := []int{80, 443, 8080, 8443, 3000}
		for _, port := range commonPorts {
			// Check context cancellation
			select {
			case <-ctx.Done():
				break
			default:
			}

			addr := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", addr, 400*time.Millisecond)
			if err == nil {
				conn.Close()
				data.OpenPorts = append(data.OpenPorts, port)
			}
		}
	}

	// 3. Scan and parse robots.txt for hidden directory lists
	baseRobotsURL := targetURL
	if !strings.HasSuffix(baseRobotsURL, "/") {
		baseRobotsURL += "/"
	}
	baseRobotsURL += "robots.txt"

	reqRobots, err := http.NewRequestWithContext(ctx, "GET", baseRobotsURL, nil)
	if err == nil {
		resp, err := client.Do(reqRobots)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(strings.ToLower(line), "disallow:") {
					parts := strings.SplitN(line, ":", 2)
					if len(parts) == 2 {
						path := strings.TrimSpace(parts[1])
						if path != "" && path != "/" {
							data.RobotsPaths = append(data.RobotsPaths, path)
						}
					}
				}
			}
		}
	}

	return data, nil
}
