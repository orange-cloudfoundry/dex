package cert

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/dexidp/dex/connector"
)

type Config struct {
	// RootCAs are the paths of the certificates for client certificate validation
	RootCAs []string `json:"rootCAs"`
	// CertHeader is the name of the HTTP header containing the client certificate (if using a proxy)
	CertHeader string `json:"certHeader"`

	UserIDKey            string `json:"userIDKey"`
	UserNameKey          string `json:"userNameKey"`
	PreferredUserNameKey string `json:"preferredUserNameKey"`
	GroupKey             string `json:"groupKey"`
}

// CertConnector implements the CallbackConnector interface
type CertConnector struct {
	rootCAs              []*x509.CertPool
	certHeader           string
	userIDKey            string
	userNameKey          string
	preferredUserNameKey string
	groupKey             string
	logger               *slog.Logger
}

// loadCACert loads the CA certificate from the file
func loadCACert(caCertFile string) (*x509.CertPool, error) {
	clientCA := x509.NewCertPool()
	caCertBytes, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert file: %v", err)
	}

	if !clientCA.AppendCertsFromPEM(caCertBytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", caCertFile)
	}

	return clientCA, nil
}

// Open initializes the PKI Connector
func (c *Config) Open(id string, logger *slog.Logger) (connector.Connector, error) {
	if len(c.RootCAs) == 0 {
		return nil, errors.New("missing required config field 'rootCAs'")
	}

	rootCAs := []*x509.CertPool{}
	for _, rootCA := range c.RootCAs {
		pool, err := loadCACert(rootCA)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA certificate: %v", err)
		}
		rootCAs = append(rootCAs, pool)
	}

	return &CertConnector{
		rootCAs:              rootCAs,
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

// ExtractCertificate extract the client certificate from the request
func (c *CertConnector) ExtractCertificate(r *http.Request) (cert *x509.Certificate, err error) {
	// Check if the certificate is in the TLS connector
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}

	// Check the header (for proxy cases)
	if c.certHeader != "" {
		certHeader := r.Header.Get(c.certHeader)
		if certHeader != "" {
			certData, err := base64.StdEncoding.DecodeString(certHeader)
			if err != nil {
				return nil, errors.New("failed decoding certificate")
			}
			cert, err := x509.ParseCertificate(certData)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			return cert, nil
		}
	}

	return nil, errors.New("no client certificate found")
}

// ValidateCertificate validates the certificate against the CA pool
func (c *CertConnector) ValidateCertificate(cert *x509.Certificate) (identity connector.Identity, err error) {
	if cert == nil {
		c.logger.Error("certificate validation failed", "error", "Certificate is nil")
		return identity, fmt.Errorf("certificate validation failed: Certificate is nil")
	}

	// Verify the certificate against all configured rootCAs
	// Only one must successfully verifies the client certificate
	validClientCertificate := true
	verificationErrors := []error{}
	for _, rootCA := range c.rootCAs {
		validClientCertificate = true
		_, err = cert.Verify(x509.VerifyOptions{
			Roots:     rootCA,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if err != nil {
			validClientCertificate = false
			verificationErrors = append(verificationErrors, err)
		}
		if validClientCertificate {
			break
		}
	}
	if !validClientCertificate {
		c.logger.Error("certificate validation failed", "errors", verificationErrors)
		return identity, fmt.Errorf("certificate validation failed: %v", verificationErrors)
	}

	// Extract value to be used as userID from certificate
	var userID string
	if c.userIDKey != "" {
		userID = getValueFromCertificate(cert, c.userIDKey)
	} else {
		defaultUserIDKey := "0.9.2342.19200300.100.1.1" // OID for UID
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
		defaultGroupKey := "2.5.4.10" // OID for Organization
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
