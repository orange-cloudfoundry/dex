package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dexidp/dex/connector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpen(t *testing.T) {
	// Create a temporary CA cert file for testing
	caFile, err := os.CreateTemp("", "ca-*.pem")
	assert.NoError(t, err, "Failed to create temp CA file")
	defer os.Remove(caFile.Name())

	// Generate a test CA certificate
	caCert, _, err := generateCACertificate()
	require.NoError(t, err, "Failed to generate CA certificate")

	// Write the CA certificate into to the temp file
	err = pem.Encode(caFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	require.NoError(t, err, "Failed to write CA cert to file")
	caFile.Close()

	// Create a config with the test CA cert file
	config := Config{
		ClientCAPath: caFile.Name(),
		CertHeader:   "X-Client-Cert",
	}

	// Create a logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Open the certConnector
	conn, err := config.Open("test-connector", logger)
	assert.NoError(t, err, "Failed to open connector")

	// Check if it implements the connector interface
	certConnector, ok := conn.(*CertConnector)
	assert.True(t, ok, "Returned connector is not a certConnector")

	assert.Equal(t, config.CertHeader, certConnector.certHeader, "Mismatched certHeader")
}

func TestLoginURL(t *testing.T) {
	certConnector := &CertConnector{}

	loginURL, err := certConnector.LoginURL(connector.Scopes{}, "https://example.com/auth/callback", "test-state")
	assert.NoError(t, err, "LoginURL failed")

	expected := "https://example.com/auth/callback?state=test-state"
	assert.Equal(t, expected, loginURL, "Unexpected LoginURL")
}

func TestHandleCallback(t *testing.T) {
	// Generate a test CA certificate
	caCert, caPrivKey, err := generateCACertificate()
	require.NoError(t, err, "Failed to generate CA certificate")

	// Generate a test client certificate
	clientCert, err := generateClientCertificate(caCert, caPrivKey)
	require.NoError(t, err, "Failed to generate client certificate")

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	certConnector := &CertConnector{
		clientCA: caPool,
		certHeader: "X-Client-Cert",
		logger: slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	// Test with valid certificate in TLS
	t.Run("ValidCertificateTLS", func(t *testing.T) {
		req := &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{clientCert},
			},
		}

		identity, err := certConnector.HandleCallback(connector.Scopes{}, req)
		assert.NoError(t, err, "HandleCallback failed")
		assert.Equal(t, "CUID2048", identity.UserID, "Unexpected UserID")
	})
	// Test with valid certificate in header
	t.Run("ValidCertificateInHeader", func(t *testing.T) {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCert.Raw})
		req := httptest.NewRequest("GET", "/callback", nil)
		req.Header.Set("X-Client-Cert", base64.StdEncoding.EncodeToString(certPEM))

		identity, err := certConnector.HandleCallback(connector.Scopes{}, req)
		assert.NoError(t, err, "HandleCallback failed")
		assert.Equal(t, "CUID2048", identity.UserID, "Unexpected UserID")
	})
	// Test with no certificate
	t.Run("NoCertificate", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/callback", nil)

		_, err := certConnector.HandleCallback(connector.Scopes{}, req)
		assert.Error(t, err, "Expected error for no certificate")
	})
}

func generateCACertificate() (*x509.Certificate, *rsa.PrivateKey, error) {
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	caTemplate := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country: []string{"FR"},
			Organization: []string{"Orange CA"},
			CommonName: "Test CA",
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour * 24),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	caCert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}

	return caCert, caPrivKey, nil
}

func generateClientCertificate(caCert *x509.Certificate, caPrivKey *rsa.PrivateKey) (*x509.Certificate, error) {
	clientPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	clientTemplate := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country: []string{"FR"},
			Organization: []string{"Orange"},
			CommonName: "Test Client",
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{0, 9, 2342, 19200300, 100, 1, 1}, // OID for UID
					Value: "CUID2048",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter: time.Now().Add(time.Hour * 24),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, &clientPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}

	clientCert, err := x509.ParseCertificate(clientBytes)
	if err != nil {
		return nil, err
	}

	return clientCert, nil
}
