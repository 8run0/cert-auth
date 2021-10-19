package service

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type TokenService interface {
	NewTokenForKey(key string) (string, error)
	IsKeyTokenValid(key string, token string) bool
}

type tokenServiceImpl struct {
	tokenManager *tokenManager
}

type tokenManager struct {
	tokenMap map[string]*token
	mu       sync.Mutex
}

type token struct {
	token  string
	expiry time.Time
}

func (t *token) isExpired() bool {
	return t.expiry.Before(time.Now())
}

func NewTokenService() TokenService {
	tokens := make(map[string]*token)
	return &tokenServiceImpl{tokenManager: &tokenManager{tokenMap: tokens}}
}

func (ts *tokenServiceImpl) NewTokenForKey(key string) (string, error) {
	tkn, err := ts.tokenManager.addTokenToTokenMapForKey(key, ts.newToken())
	if err != nil {
		return "", err
	}
	return tkn.token, nil
}

func (ts *tokenServiceImpl) newToken() *token {
	tokenValue := ts.generateSecureToken(8)
	now := time.Now()
	return &token{token: tokenValue, expiry: now.Add(time.Minute * 5)}
}

func (ts *tokenServiceImpl) generateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

func (ts *tokenServiceImpl) IsKeyTokenValid(key string, token string) bool {
	return ts.tokenManager.isKeyTokenValid(key, token)
}

func (tm *tokenManager) isKeyTokenValid(key string, token string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	// TODO Logic for duplicate checking
	stored := tm.tokenMap[key]
	if stored == nil {
		return false
	}
	if stored.isExpired() {
		return false
	}
	if stored.token != token {
		return false
	}
	if stored.token == token && !stored.isExpired() {
		return true
	}
	return false
}

func (tm *tokenManager) addTokenToTokenMapForKey(key string, token *token) (*token, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	// TODO Logic for duplicate checking
	tm.tokenMap[key] = token
	return token, nil
}
