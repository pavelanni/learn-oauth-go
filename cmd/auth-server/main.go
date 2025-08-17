package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pavelanni/learn-oauth-go/internal/logger"
	"github.com/pavelanni/learn-oauth-go/internal/oauth"
	"github.com/pavelanni/learn-oauth-go/internal/users"
)

const (
	AuthServerPort = ":8081"
	ClientID       = "demo-client"
	ClientName     = "Demo OAuth Client"
)

type AuthServer struct {
	store     *oauth.Store
	userStore *users.UserStore
	templates *template.Template
}

func NewAuthServer() (*AuthServer, error) {
	userStore, err := users.LoadUsers("data/users.json")
	if err != nil {
		return nil, fmt.Errorf("failed to load users: %w", err)
	}

	templates, err := template.ParseGlob("web/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &AuthServer{
		store:     oauth.NewStore(),
		userStore: userStore,
		templates: templates,
	}, nil
}

func (as *AuthServer) authorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	responseType := r.URL.Query().Get("response_type")

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Authorization Request",
		Payload: map[string]interface{}{
			"client_id":              clientID,
			"redirect_uri":           redirectURI,
			"scope":                  scope,
			"state":                  state,
			"code_challenge":         codeChallenge[:20] + "...",
			"code_challenge_method":  codeChallengeMethod,
			"response_type":          responseType,
		},
	})

	if responseType != "code" {
		http.Error(w, "unsupported_response_type", http.StatusBadRequest)
		return
	}

	// Check if client is the demo client or a dynamically registered client
	if clientID != ClientID && !as.store.IsValidClient(clientID) {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}

	// Validate redirect URI for dynamically registered clients
	if clientID != ClientID && !as.store.IsValidRedirectURI(clientID, redirectURI) {
		http.Error(w, "invalid_redirect_uri", http.StatusBadRequest)
		return
	}

	if codeChallengeMethod != "S256" {
		http.Error(w, "invalid_request: code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	data := map[string]interface{}{
		"ClientID":             clientID,
		"ClientName":           ClientName,
		"RedirectURI":          redirectURI,
		"Scope":                scope,
		"State":                state,
		"CodeChallenge":        codeChallenge,
		"CodeChallengeMethod":  codeChallengeMethod,
	}

	as.templates.ExecuteTemplate(w, "login.html", data)
}

func (as *AuthServer) login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")
	scope := r.FormValue("scope")
	state := r.FormValue("state")
	codeChallenge := r.FormValue("code_challenge")
	codeChallengeMethod := r.FormValue("code_challenge_method")

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "USER",
		Destination: "AUTH-SERVER",
		MessageType: "Login Attempt",
		Payload: map[string]interface{}{
			"username": username,
			"password": "[REDACTED]",
		},
	})

	user, err := as.userStore.Authenticate(username, password)
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		data := map[string]interface{}{
			"ClientID":             clientID,
			"ClientName":           ClientName,
			"RedirectURI":          redirectURI,
			"Scope":                scope,
			"State":                state,
			"CodeChallenge":        codeChallenge,
			"CodeChallengeMethod":  codeChallengeMethod,
			"Error":                "Invalid username or password",
		}
		as.templates.ExecuteTemplate(w, "login.html", data)
		return
	}

	code, err := oauth.GenerateRandomString(32)
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	authCode := &oauth.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		UserID:              user.Username,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	as.store.StoreAuthorizationCode(authCode)

	redirectURL, _ := url.Parse(redirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	query.Set("state", state)
	redirectURL.RawQuery = query.Encode()

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Authorization Response",
		Payload: map[string]interface{}{
			"code":  code,
			"state": state,
		},
	})

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

func (as *AuthServer) token(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Token Request",
		Payload: map[string]interface{}{
			"grant_type":    grantType,
			"code":          code,
			"redirect_uri":  redirectURI,
			"client_id":     clientID,
			"code_verifier": codeVerifier[:20] + "...",
		},
	})

	if grantType != "authorization_code" {
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	authCode, err := as.store.GetAuthorizationCode(code)
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	// Validate client exists (either demo client or registered client)
	if clientID != ClientID && !as.store.IsValidClient(clientID) {
		http.Error(w, "invalid_client", http.StatusBadRequest)
		return
	}

	if !oauth.VerifyPKCE(codeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		logger.LogError("AUTH-SERVER", fmt.Errorf("PKCE verification failed"))
		http.Error(w, "invalid_grant", http.StatusBadRequest)
		return
	}

	as.store.DeleteAuthorizationCode(code)

	accessToken, err := oauth.GenerateRandomString(32)
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		http.Error(w, "server_error", http.StatusInternalServerError)
		return
	}

	token := &oauth.AccessToken{
		Token:     accessToken,
		UserID:    authCode.UserID,
		ClientID:  authCode.ClientID,
		Scope:     authCode.Scope,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	as.store.StoreAccessToken(token)

	response := oauth.TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       authCode.Scope,
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Token Response",
		Payload: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        authCode.Scope,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (as *AuthServer) discovery(w http.ResponseWriter, r *http.Request) {
	metadata := oauth.DiscoveryDocument{
		Issuer:                            "http://localhost:8081",
		AuthorizationEndpoint:             "http://localhost:8081/authorize",
		TokenEndpoint:                     "http://localhost:8081/token",
		RegistrationEndpoint:              "http://localhost:8081/register",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   []string{"read"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post"},
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Discovery Request",
		Payload: map[string]interface{}{
			"endpoint": "/.well-known/oauth-authorization-server",
		},
	})

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "AUTH-SERVER", 
		Destination: "CLIENT",
		MessageType: "Discovery Response",
		Payload: map[string]interface{}{
			"issuer":                 metadata.Issuer,
			"authorization_endpoint": metadata.AuthorizationEndpoint,
			"token_endpoint":         metadata.TokenEndpoint,
			"registration_endpoint":  metadata.RegistrationEndpoint,
			"response_types_supported": metadata.ResponseTypesSupported,
			"grant_types_supported":    metadata.GrantTypesSupported,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// Dynamic Client Registration (RFC 7591)
func (as *AuthServer) clientRegistration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req oauth.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		logger.LogError("AUTH-SERVER", fmt.Errorf("invalid JSON in registration request: %w", err))
		as.sendRegistrationError(w, "invalid_request", "Invalid JSON in request body")
		return
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Client Registration Request",
		Payload: map[string]interface{}{
			"redirect_uris":     req.RedirectURIs,
			"client_name":       req.ClientName,
			"application_type":  req.ApplicationType,
			"response_types":    req.ResponseTypes,
			"grant_types":       req.GrantTypes,
		},
	})

	// Validate required fields
	if len(req.RedirectURIs) == 0 {
		as.sendRegistrationError(w, "invalid_request", "redirect_uris is required")
		return
	}

	// Generate client credentials
	clientID, err := oauth.GenerateClientID()
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		as.sendRegistrationError(w, "server_error", "Failed to generate client ID")
		return
	}

	clientSecret, err := oauth.GenerateClientSecret()
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		as.sendRegistrationError(w, "server_error", "Failed to generate client secret")
		return
	}

	// Set defaults for optional fields
	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	applicationType := req.ApplicationType
	if applicationType == "" {
		applicationType = "web"
	}

	tokenEndpointAuthMethod := req.TokenEndpointAuthMethod
	if tokenEndpointAuthMethod == "" {
		tokenEndpointAuthMethod = "client_secret_post"
	}

	// Store the registered client
	registeredClient := &oauth.RegisteredClient{
		ID:                      clientID,
		Secret:                  clientSecret,
		RedirectURIs:            req.RedirectURIs,
		ResponseTypes:           responseTypes,
		GrantTypes:              grantTypes,
		ApplicationType:         applicationType,
		Name:                    req.ClientName,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
		CreatedAt:               time.Now(),
	}
	
	as.store.StoreClient(registeredClient)

	// Create response
	response := oauth.ClientRegistrationResponse{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		RedirectURIs:            req.RedirectURIs,
		ResponseTypes:           responseTypes,
		GrantTypes:              grantTypes,
		ApplicationType:         applicationType,
		ClientName:              req.ClientName,
		TokenEndpointAuthMethod: tokenEndpointAuthMethod,
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Client Registration Response",
		Payload: map[string]interface{}{
			"client_id":                clientID,
			"client_secret":            "[REDACTED]",
			"redirect_uris":            response.RedirectURIs,
			"response_types":           response.ResponseTypes,
			"grant_types":              response.GrantTypes,
			"application_type":         response.ApplicationType,
			"client_name":              response.ClientName,
			"token_endpoint_auth_method": response.TokenEndpointAuthMethod,
		},
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (as *AuthServer) sendRegistrationError(w http.ResponseWriter, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)

	errorResponse := oauth.ErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Client Registration Error",
		Payload: map[string]interface{}{
			"error":             errorCode,
			"error_description": errorDescription,
		},
	})

	json.NewEncoder(w).Encode(errorResponse)
}

func main() {
	logger.LogInfo("AUTH-SERVER", "Starting OAuth 2.1 Authorization Server on port 8081")

	authServer, err := NewAuthServer()
	if err != nil {
		logger.LogError("AUTH-SERVER", err)
		return
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/authorize", authServer.authorize)
	r.Post("/login", authServer.login)
	r.Post("/token", authServer.token)
	r.Post("/register", authServer.clientRegistration)
	r.Get("/.well-known/oauth-authorization-server", authServer.discovery)

	logger.LogInfo("AUTH-SERVER", "Server ready to handle OAuth requests")
	if err := http.ListenAndServe(AuthServerPort, r); err != nil {
		logger.LogError("AUTH-SERVER", err)
	}
}