package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/storage"
)

type fakeClientCredentialsConnector struct {
	clientID     string
	clientSecret string
	err          error
}

func (f fakeClientCredentialsConnector) LoginWithClientCredentials(_ context.Context, _ connector.Scopes, clientID, clientSecret string) (connector.Identity, bool, error) {
	if f.err != nil {
		return connector.Identity{}, false, f.err
	}
	if clientID != f.clientID || clientSecret != f.clientSecret {
		return connector.Identity{}, false, nil
	}
	return connector.Identity{
		UserID:            "service-account-id",
		Username:          "Service Account",
		PreferredUsername: "svc-account",
		Email:             "svc@example.com",
		EmailVerified:     true,
		Groups:            []string{"robots"},
	}, true, nil
}

func TestHandleExternalClientCredentialsGrant(t *testing.T) {
	const (
		clientID           = "dex-client"
		clientSecret       = "dex-secret"
		customClientID     = "tenant-client"
		customClientSecret = "tenant-secret"
	)

	tests := []struct {
		name         string
		useBasicAuth bool
		setup        func(vals url.Values)
		connector    connector.Connector
		allowedGrant []string
		expectedCode int
		expectedErr  string
	}{
		{
			name:         "dex client credentials in form",
			expectedCode: http.StatusOK,
		},
		{
			name:         "dex client credentials in basic auth",
			useBasicAuth: true,
			expectedCode: http.StatusOK,
		},
		{
			name:         "invalid dex client secret",
			setup:        func(vals url.Values) { vals.Set("client_secret", "wrong") },
			expectedCode: http.StatusUnauthorized,
			expectedErr:  errInvalidClient,
		},
		{
			name:         "unknown dex client",
			setup:        func(vals url.Values) { vals.Set("client_id", "unknown") },
			expectedCode: http.StatusUnauthorized,
			expectedErr:  errInvalidClient,
		},
		{
			name:         "external secret rejected by the provider",
			setup:        func(vals url.Values) { vals.Set("custom_client_secret", "wrong") },
			expectedCode: http.StatusUnauthorized,
			expectedErr:  errAccessDenied,
		},
		{
			name:         "missing custom_client_secret",
			setup:        func(vals url.Values) { vals.Del("custom_client_secret") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "missing custom_client_id",
			setup:        func(vals url.Values) { vals.Del("custom_client_id") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "missing connector_id",
			setup:        func(vals url.Values) { vals.Del("connector_id") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "unknown connector",
			setup:        func(vals url.Values) { vals.Set("connector_id", "unknown") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "connector without client credentials support",
			setup:        func(vals url.Values) { vals.Set("connector_id", "mock") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "upstream failure",
			connector:    fakeClientCredentialsConnector{err: errors.New("upstream down")},
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "missing openid scope",
			setup:        func(vals url.Values) { vals.Set("scope", "email") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "unrecognized scope",
			setup:        func(vals url.Values) { vals.Set("scope", "openid unknown") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "untrusted cross client scope",
			setup:        func(vals url.Values) { vals.Set("scope", "openid audience:server:client_id:other") },
			expectedCode: http.StatusBadRequest,
			expectedErr:  errInvalidRequest,
		},
		{
			name:         "grant type not allowed",
			allowedGrant: []string{grantTypeTokenExchange},
			expectedCode: http.StatusBadRequest,
			expectedErr:  errUnsupportedGrantType,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			httpServer, s := newTestServer(t, func(c *Config) {
				if tc.allowedGrant != nil {
					c.AllowedGrantTypes = tc.allowedGrant
				}
			})
			defer httpServer.Close()

			require.NoError(t, s.storage.CreateClient(ctx, storage.Client{ID: clientID, Secret: clientSecret}))
			require.NoError(t, s.storage.CreateConnector(ctx, storage.Connector{
				ID:              "external",
				Type:            "mockCallback",
				Name:            "External",
				ResourceVersion: "1",
			}))
			var conn connector.Connector = fakeClientCredentialsConnector{clientID: customClientID, clientSecret: customClientSecret}
			if tc.connector != nil {
				conn = tc.connector
			}
			s.mu.Lock()
			s.connectors["external"] = Connector{ResourceVersion: "1", Connector: conn}
			s.mu.Unlock()

			vals := url.Values{
				"grant_type":           {grantTypeExternalClientCredentials},
				"connector_id":         {"external"},
				"scope":                {"openid email profile groups"},
				"custom_client_id":     {customClientID},
				"custom_client_secret": {customClientSecret},
			}
			if !tc.useBasicAuth {
				vals.Set("client_id", clientID)
				vals.Set("client_secret", clientSecret)
			}
			if tc.setup != nil {
				tc.setup(vals)
			}

			req := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token", strings.NewReader(vals.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.useBasicAuth {
				req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
			}
			rr := httptest.NewRecorder()

			s.handleToken(rr, req)

			require.Equal(t, tc.expectedCode, rr.Code, rr.Body.String())
			if tc.expectedCode != http.StatusOK {
				var errRes struct {
					Error string `json:"error"`
				}
				require.NoError(t, json.NewDecoder(rr.Body).Decode(&errRes))
				require.Equal(t, tc.expectedErr, errRes.Error)
				return
			}

			var res accessTokenResponse
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&res))
			require.NotEmpty(t, res.AccessToken)
			require.NotEmpty(t, res.IDToken)
			require.Empty(t, res.RefreshToken)

			claims := decodeJWTPayload(t, res.IDToken)
			require.Equal(t, clientID, claims["aud"])
			require.Equal(t, "Service Account", claims["name"])
			require.Equal(t, "svc-account", claims["preferred_username"])
			require.Equal(t, "svc@example.com", claims["email"])
			require.Equal(t, []any{"robots"}, claims["groups"])
		})
	}
}

func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}
