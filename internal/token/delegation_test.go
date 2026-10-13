package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

func TestDelegationCannotBeUsedForNormalLoginAndPreservesExpiry(t *testing.T) {
	m := testManager(t)
	now := time.Now().UTC().Truncate(time.Second)
	m.now = func() time.Time { return now }
	p := Principal{UserID: uuid.New(), SessionID: uuid.New(), ClientID: "jobpilot", ExpiresAt: now.Add(35 * time.Second)}
	raw, expires, err := m.SignDelegation(p, "http://127.0.0.1:8081/mcp", "learning_route:import learning_route:read", "request-123", strings.Repeat("a", 64))
	if err != nil || expires != p.ExpiresAt {
		t.Fatalf("expiry violated: %v %v", expires, err)
	}
	if _, err = m.Parse(raw); err == nil {
		t.Fatal("delegated token accepted as normal login")
	}
	claims := &DelegationClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &m.privateKey.PublicKey, nil }, jwt.WithAudience("http://127.0.0.1:8081/mcp"), jwt.WithIssuer("shared-auth"))
	if err != nil || !parsed.Valid || claims.Subject != p.UserID.String() || claims.ImportKey != "request-123" || !claims.Delegated {
		t.Fatal("invalid delegation claims")
	}
	p.ExpiresAt = now.Add(15 * time.Minute)
	_, expires, err = m.SignDelegation(p, "resource", "scope", "key", "digest")
	if err != nil || expires.Sub(now) != 2*time.Minute {
		t.Fatal("delegation exceeds maximum lifetime")
	}
	p.ClientID = "studyflow"
	if _, _, err = m.SignDelegation(p, "resource", "scope", "key", "digest"); err == nil {
		t.Fatal("wrong client accepted")
	}
}
