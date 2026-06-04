package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"github.com/parth/lastresort/internal/api"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/ai/v1/aiv1connect"
	"github.com/parth/lastresort/internal/gen/scan/v1/scanv1connect"
	"github.com/parth/lastresort/internal/orchestrator"
	"github.com/parth/lastresort/internal/proxy"
	"github.com/parth/lastresort/internal/storage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPathOpt := serveCmd.String("db", "./data/lastresort.db", "Path to SQLite database")
	apiPortOpt := serveCmd.Int("port", 8443, "API Server Port")
	proxyPortOpt := serveCmd.Int("proxy-port", 8080, "MITM Proxy Port")
	aiAddrOpt := serveCmd.String("ai-addr", "http://127.0.0.1:50052", "Python AI Server Address")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd.Parse(os.Args[2:])
		runServe(*dbPathOpt, *apiPortOpt, *proxyPortOpt, *aiAddrOpt)
	case "version":
		fmt.Println("LastResort v0.1.0-alpha")
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: lastresort <command> [arguments]")
	fmt.Println("Commands:")
	fmt.Println("  serve      Start the API and proxy daemon")
	fmt.Println("  version    Show version info")
}

func runServe(dbPath string, apiPort int, proxyPort int, aiAddr string) {
	log.Printf("Starting LastResort Core daemon...")

	// 1. Initialize SQLite Database
	db, err := storage.InitDB(dbPath)
	if err != nil {
		log.Fatalf("[DB] [FATAL] Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Printf("[DB] Database initialized at %s", dbPath)

	// 2. Setup certificate storage structures
	certDir := "./data/certs"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		log.Fatalf("[CERT] [FATAL] Failed to create certs directory: %v", err)
	}
	log.Printf("[CERT] Certificate storage structure created at %s", certDir)

	// 3. Initialize TLS Root CA and Cert Manager
	caCertPath := filepath.Join(certDir, "ca.crt")
	caKeyPath := filepath.Join(certDir, "ca.key")
	certManager, err := proxy.NewCertManager(caCertPath, caKeyPath)
	if err != nil {
		log.Fatalf("[CERT] [FATAL] Failed to initialize CertManager: %v", err)
	}
	log.Printf("[CERT] Loaded TLS Certificate Authority from %s", caCertPath)

	// 4. Start the MITM Proxy Server
	proxyServer := proxy.NewProxyServer(db, certManager, proxyPort)
	if err := proxyServer.Start(); err != nil {
		log.Fatalf("[PROXY] [FATAL] Failed to start MITM proxy: %v", err)
	}
	defer proxyServer.Stop()

	// 5. Connect to Python AI gRPC server via H2C HTTP/2 client
	httpClient := &http.Client{
		Transport: &http2.Transport{
			AllowHTTP: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	aiClient := aiv1connect.NewAiServiceClient(
		httpClient,
		aiAddr,
		connect.WithGRPC(), // speak standard gRPC
		connect.WithInterceptors(connect.UnaryInterceptorFunc(func(next connect.UnaryFunc) connect.UnaryFunc {
			return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
				provider, err := db.GetSetting(ctx, "ai_provider")
				if err == nil && provider != "" {
					req.Header().Set("x-ai-provider", provider)
				}
				model, err := db.GetSetting(ctx, "gemini_model")
				if err == nil && model != "" {
					req.Header().Set("x-gemini-model", model)
				}
				return next(ctx, req)
			}
		})),
	)
	log.Printf("[IPC] Configured client connection to Python AI gRPC at %s", aiAddr)

	// 6. Initialize background Scan Orchestrator
	scanOrch := orchestrator.NewOrchestrator(db, aiClient, proxyPort)

	// 7. Register ConnectRPC Services
	scanServer := api.NewScanServer(db, aiClient, scanOrch)
	mux := http.NewServeMux()
	path, handler := scanv1connect.NewScanServiceHandler(scanServer)
	mux.Handle(path, handler)

	// Register REST extension routes (hypotheses, scan-modules, etc.)
	scanServer.RegisterRestRoutes(mux)

	// Serve the reports directory statically
	mux.Handle("/reports/", http.StripPrefix("/reports/", http.FileServer(http.Dir("./data/reports"))))


	// Dynamic status check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		aiStatus := "offline"
		aiProvider := "unknown"
		aiModel := "unknown"

		// Query Python AI service health
		aiRes, err := aiClient.Health(r.Context(), connect.NewRequest(&aiv1.HealthRequest{}))
		if err == nil {
			aiStatus = aiRes.Msg.Status
			aiProvider = aiRes.Msg.Provider
			aiModel = aiRes.Msg.Model
		}

		fmt.Fprintf(w, `{"status":"ok","db":"connected","proxy":"listening","ai":{"status":"%s","provider":"%s","model":"%s"},"version":"0.1.0-alpha"}`,
			aiStatus, aiProvider, aiModel)
	})


	// 5. Add CORS middleware for UI access
	corsMux := corsMiddleware(mux)

	// 6. Start the Server (H2C enabled for HTTP/2 support without TLS for local dev)
	addr := fmt.Sprintf("127.0.0.1:%d", apiPort)
	log.Printf("[API] Server listening on http://%s", addr)
	h2Server := &http2.Server{}
	err = http.ListenAndServe(addr, h2c.NewHandler(corsMux, h2Server))
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("[API] [FATAL] Server execution failed: %v", err)
	}
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, Connect-Protocol-Version")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
