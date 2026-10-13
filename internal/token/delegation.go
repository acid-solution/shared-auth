package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

// Delegation is deliberately unusable as a normal application access token.
type DelegationClaims struct {
	SessionID     string            `json:"sid"`
	Delegated     bool              `json:"delegated"`
	Actor         map[string]string `json:"act"`
	Scope         string            `json:"scope"`
	ImportKey     string            `json:"import_key"`
	ContentDigest string            `json:"content_digest"`
	jwt.RegisteredClaims
}

func (m *Manager) SignDelegation(p Principal, audience, scope, key, digest string) (string, time.Time, error) {
	now := m.now().UTC()
	expires := now.Add(2 * time.Minute)
	if p.ExpiresAt.Before(expires) {
		expires = p.ExpiresAt
	}
	if p.ClientID != "jobpilot" || p.UserID == uuid.Nil || p.SessionID == uuid.Nil || !expires.After(now) {
		return "", time.Time{}, ErrInvalid
	}
	claims := DelegationClaims{
		SessionID: p.SessionID.String(), Delegated: true, Actor: map[string]string{"sub": "jobpilot"},
		Scope: scope, ImportKey: key, ContentDigest: digest,
		RegisteredClaims: jwt.RegisteredClaims{Issuer: m.issuer, Subject: p.UserID.String(), Audience: jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expires), IssuedAt: jwt.NewNumericDate(now), ID: uuid.NewString()},
	}
	value := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	value.Header["kid"] = m.keyID
	raw, err := value.SignedString(m.privateKey)
	return raw, expires, err
}
