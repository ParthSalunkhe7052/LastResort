package fixtures

import (
	"fmt"
	"net/http"
	"net/http/httptest"
)

// NewTargetApp creates and returns a running local httptest Server exposing vulnerable test routes.
func NewTargetApp() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
			<head><title>Test Target App</title></head>
			<body>
				<h1>Welcome to Test Target</h1>
				<a href="/login">Login Page</a>
				<a href="/unsafe-cors">CORS Test</a>
				<a href="/set-cookie">Cookie setter</a>
				<script src="/static/app.js"></script>
			</body>
		</html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
			<body>
				<h1>Login</h1>
				<form action="/dashboard" method="POST">
					<input type="text" name="username" />
					<input type="password" name="password" />
					<input type="submit" value="Submit" />
				</form>
			</body>
		</html>`)
	})

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html>
			<body>
				<h1>Dashboard</h1>
				<a href="/api/users/1">User 1 API</a>
			</body>
		</html>`)
	})

	mux.HandleFunc("/api/users/1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":1,"username":"admin"}`)
	})

	mux.HandleFunc("/api/users/2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":2,"username":"user"}`)
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		q := r.URL.Query().Get("q")
		fmt.Fprintf(w, "<html><body>Search Results for: %s</body></html>", q)
	})

	mux.HandleFunc("/unsafe-cors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	})

	mux.HandleFunc("/set-cookie", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "sessionid=abc123; Path=/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>Cookie set</body></html>`)
	})

	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		fmt.Fprintf(w, "User-agent: *\nDisallow: /hidden-admin\nSitemap: %s://%s/sitemap.xml", scheme, r.Host)
	})

	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
		<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
			<url><loc>%s://%s/search?q=test</loc></url>
		</urlset>`, scheme, r.Host)
	})

	mux.HandleFunc("/static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `fetch("/api/users/1"); console.log("/hidden-admin");`)
	})

	return httptest.NewServer(mux)
}
