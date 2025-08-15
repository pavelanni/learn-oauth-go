package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/pavelanni/learn-oauth-go/internal/logger"
	"github.com/pavelanni/learn-oauth-go/internal/oauth"
)

const (
	ClientPort        = ":8080"
	AuthServerURL     = "http://localhost:8081"
	ResourceServerURL = "http://localhost:8083"
	ClientID          = "demo-client"
	RedirectURI       = "http://localhost:8080/callback"
	Scope             = "read"
)

type Client struct {
	templates     *template.Template
	pkceChallenge *oauth.PKCEChallenge
	authCode      string
	accessToken   string
}

type PageData struct {
	Error           string
	PKCEDetails     *oauth.PKCEChallenge
	AuthURL         string
	Code            string
	AccessToken     string
	ResourceContent string
	UserInfo        string
}

func NewClient() (*Client, error) {
	templates, err := template.ParseGlob("web/templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Client{
		templates: templates,
	}, nil
}

func (c *Client) home(w http.ResponseWriter, r *http.Request) {
	pkce, err := oauth.GeneratePKCEChallenge()
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to generate PKCE challenge"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	c.pkceChallenge = pkce

	authURL := fmt.Sprintf("%s/authorize?"+
		"response_type=code&"+
		"client_id=%s&"+
		"redirect_uri=%s&"+
		"scope=%s&"+
		"state=%s&"+
		"code_challenge=%s&"+
		"code_challenge_method=%s",
		AuthServerURL,
		url.QueryEscape(ClientID),
		url.QueryEscape(RedirectURI),
		url.QueryEscape(Scope),
		url.QueryEscape("demo-state-123"),
		url.QueryEscape(pkce.Challenge),
		url.QueryEscape(pkce.Method))

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "USER-BROWSER",
		MessageType: "Authorization URL Generated",
		Payload: map[string]interface{}{
			"authorization_url": authURL,
			"pkce_challenge":    pkce.Challenge,
			"pkce_method":       pkce.Method,
		},
	})

	data := PageData{
		PKCEDetails: pkce,
		AuthURL:     authURL,
	}

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Authorization Callback",
		Payload: map[string]interface{}{
			"code":  code,
			"state": state,
			"error": errorParam,
		},
	})

	if errorParam != "" {
		data := PageData{Error: fmt.Sprintf("Authorization error: %s", errorParam)}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if code == "" {
		data := PageData{Error: "No authorization code received"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if state != "demo-state-123" {
		data := PageData{Error: "Invalid state parameter"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	// Store the authorization code for later use
	c.authCode = code

	data := PageData{
		Code:        code,
		PKCEDetails: c.pkceChallenge,
	}

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) exchange(w http.ResponseWriter, r *http.Request) {
	if c.pkceChallenge == nil {
		data := PageData{Error: "No PKCE challenge available. Please start the flow again."}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if c.authCode == "" {
		data := PageData{Error: "No authorization code available. Please complete the authorization flow first."}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {c.authCode},
		"redirect_uri":  {RedirectURI},
		"client_id":     {ClientID},
		"code_verifier": {c.pkceChallenge.Verifier},
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "AUTH-SERVER",
		MessageType: "Token Exchange Request",
		Payload: map[string]interface{}{
			"grant_type":    "authorization_code",
			"redirect_uri":  RedirectURI,
			"client_id":     ClientID,
			"code_verifier": c.pkceChallenge.Verifier[:20] + "...",
		},
	})

	resp, err := http.PostForm(AuthServerURL+"/token", tokenData)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to exchange code for token"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to read token response"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.LogError("CLIENT", fmt.Errorf("token request failed: %s", string(body)))
		data := PageData{Error: fmt.Sprintf("Token request failed: %s", string(body))}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	var tokenResponse oauth.TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to parse token response"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	c.accessToken = tokenResponse.AccessToken

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "AUTH-SERVER",
		Destination: "CLIENT",
		MessageType: "Token Exchange Response",
		Payload: map[string]interface{}{
			"access_token": tokenResponse.AccessToken,
			"token_type":   tokenResponse.TokenType,
			"expires_in":   tokenResponse.ExpiresIn,
			"scope":        tokenResponse.Scope,
		},
	})

	data := PageData{
		AccessToken: tokenResponse.AccessToken,
		PKCEDetails: c.pkceChallenge,
	}

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) resource(w http.ResponseWriter, r *http.Request) {
	if c.accessToken == "" {
		data := PageData{Error: "No access token available. Please complete the OAuth flow first."}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req, err := http.NewRequest("GET", ResourceServerURL+"/protected", nil)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to create resource request"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Outgoing,
		Source:      "CLIENT",
		Destination: "RESOURCE-SERVER",
		MessageType: "Protected Resource Request",
		Headers: map[string]string{
			"Authorization": "Bearer " + c.accessToken[:20] + "...",
		},
	})

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to access protected resource"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to read resource response"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	if resp.StatusCode != http.StatusOK {
		logger.LogError("CLIENT", fmt.Errorf("resource request failed: %s", string(body)))
		data := PageData{Error: fmt.Sprintf("Resource access failed: %s", string(body))}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	logger.LogOAuthMessage(logger.LogEntry{
		Timestamp:   time.Now(),
		Direction:   logger.Incoming,
		Source:      "RESOURCE-SERVER",
		Destination: "CLIENT",
		MessageType: "Protected Resource Response",
		Payload: map[string]interface{}{
			"content_length": len(body),
			"status":         "success",
		},
	})

	data := PageData{
		AccessToken:     c.accessToken,
		ResourceContent: string(body),
		PKCEDetails:     c.pkceChallenge,
	}

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) userinfo(w http.ResponseWriter, r *http.Request) {
	if c.accessToken == "" {
		data := PageData{Error: "No access token available. Please complete the OAuth flow first."}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req, err := http.NewRequest("GET", ResourceServerURL+"/userinfo", nil)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to create userinfo request"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	req.Header.Set("Authorization", "Bearer "+c.accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to get user info"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.LogError("CLIENT", err)
		data := PageData{Error: "Failed to read userinfo response"}
		c.templates.ExecuteTemplate(w, "client.html", data)
		return
	}

	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
		prettyJSON.Write(body)
	}

	data := PageData{
		AccessToken: c.accessToken,
		UserInfo:    prettyJSON.String(),
		PKCEDetails: c.pkceChallenge,
	}

	c.templates.ExecuteTemplate(w, "client.html", data)
}

func (c *Client) status(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"has_pkce_challenge": c.pkceChallenge != nil,
		"has_access_token":   c.accessToken != "",
		"timestamp":          time.Now().Format(time.RFC3339),
	}

	if c.pkceChallenge != nil {
		status["pkce_challenge"] = c.pkceChallenge.Challenge[:20] + "..."
	}

	if c.accessToken != "" {
		status["access_token"] = c.accessToken[:20] + "..."
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func main() {
	logger.LogInfo("CLIENT", "Starting OAuth 2.1 Demo Client on port 8080")

	client, err := NewClient()
	if err != nil {
		logger.LogError("CLIENT", err)
		return
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/", client.home)
	r.Get("/callback", client.callback)
	r.Get("/exchange", client.exchange)
	r.Get("/resource", client.resource)
	r.Get("/userinfo", client.userinfo)
	r.Get("/status", client.status)
	
	// Handle common browser requests to avoid 404s in logs
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	r.Get("/_static/*", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })

	logger.LogInfo("CLIENT", "Client ready to start OAuth flow")
	logger.LogInfo("CLIENT", "Visit http://localhost:8080 to begin")
	
	if err := http.ListenAndServe(ClientPort, r); err != nil {
		logger.LogError("CLIENT", err)
	}
}