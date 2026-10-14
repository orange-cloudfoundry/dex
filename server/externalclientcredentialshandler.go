package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/storage"
)

// handleExternalClientCredentialsGrant handles the external_client_credentials grant.
//
// The dex client authenticates as for any other grant (client_id and client_secret).
// The custom_client_id and custom_client_secret are then sent to the token endpoint of the
// upstream provider behind the connector given by connector_id (client_credentials grant),
// and the identity carried by the issued token is turned into a dex token for the dex client.
func (s *Server) handleExternalClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client storage.Client) {
	ctx := r.Context()
	q := r.Form

	customClientID := q.Get("custom_client_id")
	customClientSecret := q.Get("custom_client_secret")
	if customClientID == "" || customClientSecret == "" {
		s.tokenErrHelper(w, errInvalidRequest, "Required params: custom_client_id, custom_client_secret.", http.StatusBadRequest)
		return
	}

	nonce := q.Get("nonce")
	// Some clients, like the old go-oidc, provide extra whitespace. Tolerate this.
	scopes := strings.Fields(q.Get("scope"))

	var (
		unrecognized  []string
		invalidScopes []string
	)
	hasOpenIDScope := false
	for _, scope := range scopes {
		switch scope {
		case scopeOpenID:
			hasOpenIDScope = true
		case scopeOfflineAccess, scopeEmail, scopeProfile, scopeGroups, scopeFederatedID:
		default:
			peerID, ok := parseCrossClientScope(scope)
			if !ok {
				unrecognized = append(unrecognized, scope)
				continue
			}

			isTrusted, err := s.validateCrossClientTrust(ctx, client.ID, peerID)
			if err != nil {
				s.logger.ErrorContext(ctx, "error validating cross client trust", "client_id", client.ID, "peer_id", peerID, "err", err)
				s.tokenErrHelper(w, errInvalidClient, "Error validating cross client trust.", http.StatusBadRequest)
				return
			}
			if !isTrusted {
				invalidScopes = append(invalidScopes, scope)
			}
		}
	}
	if !hasOpenIDScope {
		s.tokenErrHelper(w, errInvalidRequest, `Missing required scope(s) ["openid"].`, http.StatusBadRequest)
		return
	}
	if len(unrecognized) > 0 {
		s.tokenErrHelper(w, errInvalidRequest, fmt.Sprintf("Unrecognized scope(s) %q", unrecognized), http.StatusBadRequest)
		return
	}
	if len(invalidScopes) > 0 {
		s.tokenErrHelper(w, errInvalidRequest, fmt.Sprintf("Client can't request scope(s) %q", invalidScopes), http.StatusBadRequest)
		return
	}

	connID := q.Get("connector_id")
	if connID == "" {
		s.tokenErrHelper(w, errInvalidRequest, "No connector_id provided", http.StatusBadRequest)
		return
	}
	conn, err := s.getConnector(ctx, connID)
	if err != nil {
		s.tokenErrHelper(w, errInvalidRequest, "Requested connector does not exist.", http.StatusBadRequest)
		return
	}
	clientCredentialsConnector, ok := conn.Connector.(connector.ClientCredentialsConnector)
	if !ok {
		s.tokenErrHelper(w, errInvalidRequest, "Requested connector does not support client credentials.", http.StatusBadRequest)
		return
	}

	identity, ok, err := clientCredentialsConnector.LoginWithClientCredentials(ctx, parseScopes(scopes), customClientID, customClientSecret)
	if err != nil {
		s.logger.ErrorContext(ctx, "failed to login with external client credentials", "client_id", client.ID, "custom_client_id", customClientID, "connector_id", connID, "err", err)
		s.tokenErrHelper(w, errInvalidRequest, "Could not login with the external client credentials", http.StatusBadRequest)
		return
	}
	if !ok {
		s.logger.InfoContext(ctx, "external client credentials rejected by connector", "client_id", client.ID, "custom_client_id", customClientID, "connector_id", connID)
		s.tokenErrHelper(w, errAccessDenied, "Invalid external client credentials.", http.StatusUnauthorized)
		return
	}

	claims := storage.Claims{
		UserID:            identity.UserID,
		Username:          identity.Username,
		PreferredUsername: identity.PreferredUsername,
		Email:             identity.Email,
		EmailVerified:     identity.EmailVerified,
		Groups:            identity.Groups,
	}

	accessToken, _, err := s.newAccessToken(ctx, client.ID, claims, scopes, nonce, connID)
	if err != nil {
		s.logger.ErrorContext(ctx, "external client credentials grant failed to create new access token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	idToken, expiry, err := s.newIDToken(ctx, client.ID, claims, scopes, nonce, accessToken, "", connID)
	if err != nil {
		s.logger.ErrorContext(ctx, "external client credentials grant failed to create new ID token", "err", err)
		s.tokenErrHelper(w, errServerError, "", http.StatusInternalServerError)
		return
	}

	// No refresh token: the client can authenticate again whenever it needs a new token.
	s.writeAccessToken(w, s.toAccessTokenResponse(idToken, accessToken, "", expiry))
}
