package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CertManager handles Root CA loading/generation and dynamic signing of leaf certificates.
type CertManager struct {
	caCert     *x509.Certificate
	caKey      *rsa.PrivateKey
	certCache  map[string]*tls.Certificate
	cacheMu    sync.RWMutex
}

// NewCertManager initializes a new CertManager with CA paths.
func NewCertManager(certPath, keyPath string) (*CertManager, error) {
	cm := &CertManager{
		certCache: make(map[string]*tls.Certificate),
	}

	// Generate CA if not exists
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		if err := GenerateAndSaveCA(certPath, keyPath); err != nil {
			return nil, fmt.Errorf("failed to generate Root CA: %w", err)
		}
	}

	// Load CA
	caCertPem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert file: %w", err)
	}
	caKeyPem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA key file: %w", err)
	}

	// Parse cert
	certBlock, _ := pem.Decode(caCertPem)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}
	cm.caCert = caCert

	// Parse key
	keyBlock, _ := pem.Decode(caKeyPem)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA key PEM")
	}
	
	// Support PKCS8 (marshaled by GenerateAndSaveCA) and PKCS1 keys
	var caKey *rsa.PrivateKey
	if parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		var ok bool
		caKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("loaded CA key is not an RSA private key")
		}
	} else if parsedKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err == nil {
		caKey = parsedKey
	} else {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}
	cm.caKey = caKey

	return cm, nil
}

// GetCertificate returns a signed leaf certificate for the given domain.
// It retrieves it from the memory cache if available, otherwise signs a new one.
func (cm *CertManager) GetCertificate(host string) (*tls.Certificate, error) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	cm.cacheMu.RLock()
	cert, exists := cm.certCache[host]
	cm.cacheMu.RUnlock()

	if exists {
		return cert, nil
	}

	// Generate and sign new certificate
	certPem, keyPem, err := signHostCertificate(cm.caCert, cm.caKey, host)
	if err != nil {
		return nil, fmt.Errorf("failed to sign host certificate: %w", err)
	}

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("failed to create x509 key pair: %w", err)
	}

	cm.cacheMu.Lock()
	cm.certCache[host] = &tlsCert
	cm.cacheMu.Unlock()

	return &tlsCert, nil
}

// GenerateAndSaveCA generates a root CA certificate and key, and saves them to paths.
func GenerateAndSaveCA(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// Create directories if missing
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:  []string{"LastResort MITM Authority"},
			Country:       []string{"US"},
			Province:      []string{"State"},
			Locality:      []string{"City"},
			StreetAddress: []string{"Security Ave"},
			PostalCode:    []string{"00000"},
			CommonName:    "LastResort Root CA",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Write cert
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	// Write key
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

// signHostCertificate generates a certificate for target domain signed by the CA.
func signHostCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey, host string) ([]byte, []byte, error) {
	// Strip wildcard characters for prefix/suffix match in PKIX CN if needed, 
	// though CN can contain wildcards like *.example.com
	host = strings.TrimSpace(host)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"LastResort MITM Dynamic Cert"},
			CommonName:   host,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().AddDate(1, 0, 0), // 1 year

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	return certPem, keyPem, nil
}
