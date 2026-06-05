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

// TechFingerprint holds the result of static tech detection.
type TechFingerprint struct {
	Technologies []string
	AuthModel    string
}

// DetectTechStack inspects HTTP response headers and Set-Cookie names to
// deterministically identify the tech stack and authentication model.
// No AI is involved.
func DetectTechStack(headers map[string]string, cookies []string) TechFingerprint {
	var techs []string
	seen := make(map[string]bool)

	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			techs = append(techs, t)
		}
	}

	// Normalise header map for case-insensitive lookup.
	norm := make(map[string]string, len(headers))
	for k, v := range headers {
		norm[strings.ToLower(k)] = strings.ToLower(v)
	}

	get := func(key string) string { return norm[strings.ToLower(key)] }

	// --- Server header ---
	server := get("server")
	switch {
	case strings.Contains(server, "nginx"):
		add("Nginx")
	case strings.Contains(server, "apache"):
		add("Apache")
	case strings.Contains(server, "iis"):
		add("IIS")
	case strings.Contains(server, "lighttpd"):
		add("Lighttpd")
	case strings.Contains(server, "caddy"):
		add("Caddy")
	case strings.Contains(server, "openresty"):
		add("OpenResty")
	case strings.Contains(server, "gunicorn"):
		add("Gunicorn")
	case strings.Contains(server, "jetty"):
		add("Jetty")
	case strings.Contains(server, "tomcat"):
		add("Tomcat")
	}

	// --- X-Powered-By ---
	xpb := get("x-powered-by")
	switch {
	case strings.Contains(xpb, "php"):
		add("PHP")
	case strings.Contains(xpb, "asp.net"):
		add("ASP.NET")
	case strings.Contains(xpb, "express"):
		add("Express.js")
	case strings.Contains(xpb, "django"):
		add("Django")
	case strings.Contains(xpb, "rails"):
		add("Ruby on Rails")
	case strings.Contains(xpb, "next.js"):
		add("Next.js")
	case strings.Contains(xpb, "laravel"):
		add("Laravel")
	}

	// --- X-AspNet-Version / X-AspNetMvc-Version ---
	if v := get("x-aspnet-version"); v != "" {
		add("ASP.NET")
	}
	if v := get("x-aspnetmvc-version"); v != "" {
		add("ASP.NET MVC")
	}

	// --- X-Generator / X-Drupal-Cache / X-WordPress-... ---
	gen := get("x-generator")
	switch {
	case strings.Contains(gen, "drupal"):
		add("Drupal")
	case strings.Contains(gen, "wordpress"):
		add("WordPress")
	case strings.Contains(gen, "joomla"):
		add("Joomla")
	}
	if get("x-drupal-cache") != "" {
		add("Drupal")
	}
	if get("x-wordpress-cache") != "" || get("x-wp-cache") != "" {
		add("WordPress")
	}

	// --- Via / CF-Ray (CDN fingerprinting) ---
	via := get("via")
	if strings.Contains(via, "cloudflare") || get("cf-ray") != "" {
		add("Cloudflare")
	}
	if strings.Contains(via, "varnish") || get("x-varnish") != "" {
		add("Varnish Cache")
	}

	// --- Content-Security-Policy hints ---
	csp := get("content-security-policy")
	if strings.Contains(csp, "wp-content") {
		add("WordPress")
	}

	// --- Set-Cookie fingerprinting for auth model ---
	authModel := "Unknown"
	for _, c := range cookies {
		cl := strings.ToLower(c)
		switch {
		case strings.Contains(cl, "jsessionid"):
			add("Java/Servlet")
			authModel = "Cookie-based Session (Java)"
		case strings.Contains(cl, "phpsessid"):
			add("PHP")
			authModel = "Cookie-based Session (PHP)"
		case strings.Contains(cl, "laravel_session"):
			add("Laravel")
			authModel = "Cookie-based Session (Laravel)"
		case strings.Contains(cl, "asp.net_sessionid"):
			add("ASP.NET")
			authModel = "Cookie-based Session (ASP.NET)"
		case strings.Contains(cl, "express:sess") || strings.Contains(cl, "connect.sid"):
			add("Express.js")
			authModel = "Cookie-based Session (Express)"
		case strings.Contains(cl, "django") || strings.Contains(cl, "csrftoken"):
			add("Django")
			if authModel == "Unknown" {
				authModel = "Cookie-based Session (Django)"
			}
		case strings.Contains(cl, "ci_session"):
			add("CodeIgniter")
			authModel = "Cookie-based Session (CodeIgniter)"
		case strings.Contains(cl, "wordpress_logged_in") || strings.Contains(cl, "wp_"):
			add("WordPress")
			authModel = "WordPress Auth Cookie"
		case strings.Contains(cl, "__cfduid") || strings.Contains(cl, "cf_clearance"):
			add("Cloudflare")
		}
	}

	// Auth model heuristics from headers when cookies gave nothing useful.
	if authModel == "Unknown" {
		wwwAuth := get("www-authenticate")
		switch {
		case strings.Contains(wwwAuth, "bearer"):
			authModel = "Bearer Token (JWT/OAuth2)"
		case strings.Contains(wwwAuth, "basic"):
			authModel = "HTTP Basic Authentication"
		case strings.Contains(wwwAuth, "digest"):
			authModel = "HTTP Digest Authentication"
		default:
			if get("set-cookie") != "" {
				authModel = "Cookie-based Session"
			}
		}
	}

	if len(techs) == 0 {
		techs = append(techs, "Unknown Stack")
	}

	return TechFingerprint{
		Technologies: techs,
		AuthModel:    authModel,
	}
}

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
