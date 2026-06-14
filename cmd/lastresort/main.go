package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"connectrpc.com/connect"
	"github.com/parth/lastresort/internal/ai"
	"github.com/parth/lastresort/internal/api"
	"github.com/parth/lastresort/internal/attack"
	aiv1 "github.com/parth/lastresort/internal/gen/ai/v1"
	"github.com/parth/lastresort/internal/gen/scan/v1/scanv1connect"
	"github.com/parth/lastresort/internal/orchestrator"
	"github.com/parth/lastresort/internal/storage"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func loadDotEnv() {
	file, err := os.Open(".env")
	if err != nil {
		return
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return
	}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			if (strings.HasPrefix(value, "\"") && strings.HasSuffix(value, "\"")) ||
				(strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'")) {
				value = value[1 : len(value)-1]
			}
			if os.Getenv(key) == "" {
				os.Setenv(key, value)
			}
		}
	}
}

func main() {
	loadDotEnv()
	serveCmd := flag.NewFlagSet("serve", flag.ExitOnError)
	dbPathOpt := serveCmd.String("db", "./data/lastresort.db", "Path to SQLite database")
	apiPortOpt := serveCmd.Int("port", 8443, "API Server Port")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd.Parse(os.Args[2:])
		runServe(*dbPathOpt, *apiPortOpt)
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
	fmt.Println("  serve      Start the API daemon")
	fmt.Println("  version    Show version info")
}

func runServe(dbPath string, apiPort int) {
	log.Printf("Starting LastResort Core daemon...")

	// 1. Initialize SQLite Database
	db, err := storage.InitDB(dbPath)
	if err != nil {
		log.Fatalf("[DB] [FATAL] Failed to initialize database: %v", err)
	}
	defer db.Close()
	log.Printf("[DB] Database initialized at %s", dbPath)

	// Initialize Nuclei Templates if nuclei binary is available
	go attack.InitNucleiTemplates()

	// 2. Initialize the Go-native AI client
	aiClient := ai.NewLocalServiceClient(db)
	log.Printf("[LLM] Initialized Go-native Gemini/OpenRouter AI service client")

	// 3. Initialize background Scan Orchestrator
	// No proxy port parameter needed now (passed as 0)
	scanOrch := orchestrator.NewOrchestrator(db, aiClient, 0)

	// 4. Register ConnectRPC Services
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

		// Query local Go AI client health
		aiRes, err := aiClient.Health(r.Context(), connect.NewRequest(&aiv1.HealthRequest{}))
		if err == nil {
			aiStatus = aiRes.Msg.Status
			aiProvider = aiRes.Msg.Provider
			aiModel = aiRes.Msg.Model
		}

		fmt.Fprintf(w, `{"status":"ok","db":"connected","proxy":"disabled","ai":{"status":"%s","provider":"%s","model":"%s"},"version":"0.1.0-alpha"}`,
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
