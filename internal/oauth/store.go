package oauth

import (
	"fmt"
	"sync"
	"time"
)

type Store struct {
	codes  map[string]*AuthorizationCode
	tokens map[string]*AccessToken
	mu     sync.RWMutex
}

func NewStore() *Store {
	return &Store{
		codes:  make(map[string]*AuthorizationCode),
		tokens: make(map[string]*AccessToken),
	}
}

func (s *Store) StoreAuthorizationCode(code *AuthorizationCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
}

func (s *Store) GetAuthorizationCode(code string) (*AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	authCode, exists := s.codes[code]
	if !exists {
		return nil, fmt.Errorf("authorization code not found")
	}
	
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code expired")
	}
	
	return authCode, nil
}

func (s *Store) DeleteAuthorizationCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.codes, code)
}

func (s *Store) StoreAccessToken(token *AccessToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.Token] = token
}

func (s *Store) GetAccessToken(token string) (*AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	accessToken, exists := s.tokens[token]
	if !exists {
		return nil, fmt.Errorf("access token not found")
	}
	
	if time.Now().After(accessToken.ExpiresAt) {
		return nil, fmt.Errorf("access token expired")
	}
	
	return accessToken, nil
}

func (s *Store) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	now := time.Now()
	
	for code, authCode := range s.codes {
		if now.After(authCode.ExpiresAt) {
			delete(s.codes, code)
		}
	}
	
	for token, accessToken := range s.tokens {
		if now.After(accessToken.ExpiresAt) {
			delete(s.tokens, token)
		}
	}
}