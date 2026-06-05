package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/parth/lastresort/internal/storage"
)

// ProxyServer is the intercepting MITM HTTP/HTTPS proxy
type ProxyServer struct {
	db            *storage.DB
	certManager   *CertManager
	analyzer      *PassiveAnalyzer
	port          int
	listener      net.Listener
	wg            sync.WaitGroup
	shutdown      chan struct{}
	forwardClient *http.Client
}

// NewProxyServer creates a new ProxyServer instance.
func NewProxyServer(db *storage.DB, cm *CertManager, port int) *ProxyServer {
	return &ProxyServer{
		db:          db,
		certManager: cm,
		analyzer:    NewPassiveAnalyzer(db),
		port:        port,
		shutdown:    make(chan struct{}),
		forwardClient: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Start boots the proxy server on its configured port in a background loop.
func (p *ProxyServer) Start() error {
	addr := fmt.Sprintf("127.0.0.1:%d", p.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	p.listener = l
	log.Printf("[Proxy] Intercepting MITM proxy listening on http://%s", addr)

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				select {
				case <-p.shutdown:
					return
				default:
					log.Printf("[Proxy] [ERROR] Accept error: %v", err)
					continue
				}
			}
			go p.handleConnection(conn)
		}
	}()

	return nil
}

// Stop terminates the proxy server listener.
func (p *ProxyServer) Stop() {
	close(p.shutdown)
	if p.listener != nil {
		p.listener.Close()
	}
	p.wg.Wait()
	log.Printf("[Proxy] Proxy server stopped.")
}

func (p *ProxyServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleHTTPS(conn, req)
	} else {
		p.handleHTTP(conn, req)
	}
}

// handleHTTP handles plain HTTP requests passing through the proxy
func (p *ProxyServer) handleHTTP(conn net.Conn, req *http.Request) {
	// Reconstruct request URL if absolute URL is parsed (typical for proxies)
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
	}

	// Capture Scan ID
	scanID := req.Header.Get("X-LastResort-Scan-ID")
	req.Header.Del("X-LastResort-Scan-ID")

	// Check if in scope
	targetURL := p.getTargetURL(scanID)
	inScope := IsInScope(req.Host, targetURL)

	// Strip hop-by-hop headers before forwarding
	req.RequestURI = ""
	req.Header.Del("Proxy-Connection")

	// Perform standard roundtrip to destination
	resp, err := p.forwardClient.Do(req)
	if err != nil {
		respError(conn, http.StatusBadGateway, fmt.Sprintf("Bad Gateway: %v", err))
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[Proxy] [ERROR] Failed to read response body: %v", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(respBody))

	// Write response back to client
	if err := resp.Write(conn); err != nil {
		log.Printf("[Proxy] [ERROR] Failed to write response to client: %v", err)
	}

	// Log in background if in scope
	if inScope && scanID != "" {
		go p.logFlowAndAnalyze(scanID, req.Method, req.URL.String(), req.Header, reqBody, resp.Header, respBody, resp.StatusCode)
	}
}

// handleHTTPS handles CONNECT tunnels and negotiates MITM TLS decryption
func (p *ProxyServer) handleHTTPS(clientConn net.Conn, req *http.Request) {
	host := req.Host

	// Respond 200 to establish tunnel
	_, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		return
	}

	// Sign a dynamic cert for host
	tlsCert, err := p.certManager.GetCertificate(host)
	if err != nil {
		log.Printf("[Proxy] [ERROR] Failed to get dynamic certificate for %s: %v", host, err)
		return
	}

	// Negotiate TLS Server Handshake on the client conn
	// Force HTTP/1.1 to avoid HTTP/2 negotiation for easier inspection
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
		NextProtos:   []string{"http/1.1"},
	}
	clientTLS := tls.Server(clientConn, tlsConfig)
	if err := clientTLS.Handshake(); err != nil {
		return
	}
	defer clientTLS.Close()

	// Connect to destination server over TLS
	// Force http/1.1 request
	serverConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		return
	}
	defer serverConn.Close()

	serverTLS := tls.Client(serverConn, &tls.Config{
		ServerName: strings.Split(host, ":")[0],
		NextProtos: []string{"http/1.1"},
	})
	if err := serverTLS.Handshake(); err != nil {
		return
	}
	defer serverTLS.Close()

	// Sequentially read and forward requests and responses
	clientReader := bufio.NewReader(clientTLS)
	serverReader := bufio.NewReader(serverTLS)

	for {
		innerReq, err := http.ReadRequest(clientReader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return
		}

		var reqBody []byte
		if innerReq.Body != nil {
			var err error
			reqBody, err = io.ReadAll(innerReq.Body)
			if err != nil {
				log.Printf("[Proxy] [ERROR] Failed to read HTTPS request body: %v", err)
			}
			innerReq.Body = io.NopCloser(bytes.NewReader(reqBody))
		}

		// Parse scan ID header
		scanID := innerReq.Header.Get("X-LastResort-Scan-ID")
		innerReq.Header.Del("X-LastResort-Scan-ID")

		targetURL := p.getTargetURL(scanID)
		inScope := IsInScope(host, targetURL)

		// Forward request to destination TLS server
		innerReq.RequestURI = ""
		err = innerReq.Write(serverTLS)
		if err != nil {
			return
		}

		// Read response from destination server
		innerResp, err := http.ReadResponse(serverReader, innerReq)
		if err != nil {
			return
		}

		respBody, err := io.ReadAll(innerResp.Body)
		if err != nil {
			log.Printf("[Proxy] [ERROR] Failed to read HTTPS response body: %v", err)
		}
		innerResp.Body = io.NopCloser(bytes.NewReader(respBody))

		// Write response back to TLS client
		err = innerResp.Write(clientTLS)
		if err != nil {
			innerResp.Body.Close()
			return
		}
		innerResp.Body.Close()

		// Reconstruct request URL for DB logging
		scheme := "https"
		fullURL := fmt.Sprintf("%s://%s%s", scheme, host, innerReq.URL.RequestURI())

		// Log and analyze passively in background
		if inScope && scanID != "" {
			go p.logFlowAndAnalyze(scanID, innerReq.Method, fullURL, innerReq.Header, reqBody, innerResp.Header, respBody, innerResp.StatusCode)
		}
	}
}

func (p *ProxyServer) logFlowAndAnalyze(scanID, method, urlStr string, reqHeaders http.Header, reqBody []byte, respHeaders http.Header, respBody []byte, respStatus int) {
	ctx := context.Background()

	// 1. Save flow to DB
	flowID, err := p.db.SaveFlow(ctx, scanID, method, urlStr, reqHeaders, reqBody, respHeaders, respBody, respStatus)
	if err != nil {
		log.Printf("[Proxy] [ERROR] Failed to save HTTP flow to database: %v", err)
		return
	}

	// 2. Perform passive scanning on traffic
	p.analyzer.AnalyzeFlow(ctx, scanID, flowID, method, urlStr, reqHeaders, respHeaders, respStatus)
}

func (p *ProxyServer) getTargetURL(scanID string) string {
	if scanID == "" {
		return ""
	}
	var targetURL string
	err := p.db.QueryRowContext(context.Background(), "SELECT target_url FROM scans WHERE id = ?", scanID).Scan(&targetURL)
	if err != nil {
		return ""
	}
	return targetURL
}

func respError(conn net.Conn, status int, text string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s", 
		status, http.StatusText(status), text)
}
