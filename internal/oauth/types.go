package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"
)

type AuthorizationRequest struct {
	ClientID            string `json:"client_id" form:"client_id"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri"`
	Scope               string `json:"scope" form:"scope"`
	State               string `json:"state" form:"state"`
	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`
	ResponseType        string `json:"response_type" form:"response_type"`
}

type AuthorizationResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type TokenRequest struct {
	GrantType    string `json:"grant_type" form:"grant_type"`
	Code         string `json:"code" form:"code"`
	RedirectURI  string `json:"redirect_uri" form:"redirect_uri"`
	ClientID     string `json:"client_id" form:"client_id"`
	CodeVerifier string `json:"code_verifier" form:"code_verifier"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AuthorizationCode struct {
	Code              string
	ClientID          string
	RedirectURI       string
	Scope             string
	UserID            string
	CodeChallenge     string
	CodeChallengeMethod string
	ExpiresAt         time.Time
}

type AccessToken struct {
	Token     string
	UserID    string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

type Client struct {
	ID          string
	RedirectURI string
	Name        string
}

type PKCEChallenge struct {
	Verifier  string
	Challenge string
	Method    string
}

func GenerateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

func GeneratePKCEChallenge() (*PKCEChallenge, error) {
	verifier, err := GenerateRandomString(43)
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])

	return &PKCEChallenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
	}, nil
}

func VerifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" {
		return false
	}

	hash := sha256.Sum256([]byte(verifier))
	expectedChallenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
	
	return expectedChallenge == challenge
}