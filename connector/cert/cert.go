package cert

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/dexidp/dex/connector"
)

type Config struct {
	// ClientCAPath is the path of the CA certificate used to validate client certificates
	ClientCAPath         string `json:"clientCAPath"`
	// CertHeader is the name of the HTTP header containing the client certificate (if using a proxy)
	CertHeader           string `json:"certHeader"`

	UserIDKey            string `json:"userIDKey"`
	UserNameKey          string `json:"userNameKey"`
	PreferredUserNameKey string `json:"preferredUserNameKey"`
	GroupKey             string `json:"groupKey"`
}

// CertConnector implements the CallbackConnector interface
type CertConnector struct {
	clientCA             *x509.CertPool
	certHeader           string
	userIDKey            string
	userNameKey          string
	preferredUserNameKey string
	groupKey             string
	logger               *slog.Logger
}

var (
	_ connector.CallbackConnector = (*CertConnector)(nil)
)

// loadCACert loads the CA certificate from the file
func loadCACert(caCertFile string) (*x509.CertPool, error) {
	clientCA := x509.NewCertPool()
	caCertBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert file: %v", err)
	}

	if !clientCA.AppendCertsFromPEM(caCertBytes) {
		return nil, errors.New("failed to append CA certs from PEM file")
	}

	return clientCA, nil
}

// Open initializes the PKI Connector
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	if c.ClientCAPath == "" {
		return nil, errors.New("missing required config field 'clientCAPath'")
	}

	// TODO: maybe support multiple CAs
	clientCA, err := loadCACert(c.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA certificate: %v", err)
	}

	return &CertConnector {
		clientCA:             clientCA,
		certHeader:           c.CertHeader,
		userIDKey:            c.UserIDKey,
		userNameKey:          c.UserNameKey,
		preferredUserNameKey: c.PreferredUserNameKey,
		groupKey:             c.GroupKey,
		logger:               logger,
	}, nil
}

// Close is a no-op for this connector
func (c *CertConnector) Close() error {
	return nil
}

// LoginURL implements connector.CallbackConnector
func (c *CertConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	u, err := url.Parse(callbackURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse callback URL: %v", err)
	}

	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()

	return u.String(), nil
}

// HandleCallback implements connector.CallbackConnector
func (c *CertConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	cert, err := c.ExtractCertificate(r)
	if err != nil {
		c.logger.Error("failed to extract certificate", "error", err)
		return identity, err
	}

	return c.ValidateCertificate(r.Context(), cert)
}

// ExtractCertificate extract the client certificate from the request
func (c *CertConnector) ExtractCertificate(r *http.Request) (*x509.Certificate, error) {
	// Check if the certificate is in the TLS connector
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}

	// Check the header (for proxy cases)
	c.logger.Debug("I have this cerHeader configured", "certHeader", c.certHeader)
	if c.certHeader != "" {
		certHeader := r.Header.Get(c.certHeader)
		if certHeader != "" {
			certData, err := base64.StdEncoding.DecodeString(certHeader)
			if err != nil {
				return nil, errors.New("failed decoding certificate PEM")
			}
			block, _ := pem.Decode([]byte(certData))
			if block == nil {
				return nil, errors.New("failed to parse certificate PEM")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			return cert, nil
		}
	}

	return nil, errors.New("no client certificate found")
}

// ValidateCertificate validates the certificate against the CA pool (implements CertificateConnector)
func (c *CertConnector) ValidateCertificate(ctx context.Context, cert *x509.Certificate) (identity connector.Identity, err error) {
	// Verify the certificate
	_, err = cert.Verify(x509.VerifyOptions{
		Roots: c.clientCA,
		// TODO maybe more verification options?
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		c.logger.Error("certificate validation failed", "error", err)
		return identity, fmt.Errorf("certificate validation failed: %v", err)
	}

	// Extract value to be used as userID from certificate
	var userID string
	if c.userIDKey != "" {
		userID = getValueFromCertificate(cert, c.userIDKey)
	} else {
		defaultUserIDKey := "0.9.2342.19200300.100.1.1"  // OID for UID
		userID = getValueFromCertificate(cert, defaultUserIDKey)
	}
	// safe guard
	if userID == "" {
		userID = cert.Subject.CommonName
	}

	// Extract value to be used as username from certificate
	var userName string
	if c.userNameKey != "" {
		userName = getValueFromCertificate(cert, c.userNameKey)
	} else {
		userName = cert.Subject.CommonName
	}

	// Extract value to be used as preferredUsername from certificate
	var preferredUserName string
	if c.preferredUserNameKey != "" {
		preferredUserName = getValueFromCertificate(cert, c.preferredUserNameKey)
	} else {
		preferredUserName = userName
	}

	// Extract email from certificate
	var email string
	if cert.EmailAddresses != nil && len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}

	// Extract organization from certificate (used as a group identifier)
	var groups []string
	if c.groupKey != "" {
		groups = append(groups, getValueFromCertificate(cert, c.groupKey))
	} else {
		defaultGroupKey := "2.5.4.10"  // OID for Organization
		groups = append(groups, getValueFromCertificate(cert, defaultGroupKey))
	}

	// Extract identity information from the certificate
	identity = connector.Identity{
		UserID:            userID,
		Username:          userName,
		PreferredUsername: preferredUserName,
		Email:             email,
		EmailVerified:     false,
		Groups:            groups,
	}

	c.logger.Info("certificate validation successful", "user", identity, "subject", cert.Subject)
	return identity, nil
}

func getValueFromCertificate(cert *x509.Certificate, key string) string {
	var value string
	for _, name := range cert.Subject.Names {
		if name.Type.String() == key {
			value = name.Value.(string)
			break
		}
	}
	return value
}
