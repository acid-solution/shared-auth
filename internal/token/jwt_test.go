package token

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testManager(t *testing.T) *Manager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	contents := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustPKCS8(t, key)})
	manager, err := NewManagerPEM(contents, "test-key", "shared-auth", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func mustPKCS8(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	result, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSignParseAndJWKS(t *testing.T) {
	manager := testManager(t)
	userID, sessionID := uuid.New(), uuid.New()
	raw, _, err := manager.Sign(userID, sessionID, "jobpilot")
	if err != nil {
		t.Fatal(err)
	}
	principal, err := manager.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID != userID || principal.SessionID != sessionID || principal.ClientID != "jobpilot" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	keys := manager.JWKS()
	if len(keys.Keys) != 1 || keys.Keys[0].KID != "test-key" || keys.Keys[0].N == "" {
		t.Fatalf("unexpected JWKS: %+v", keys)
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	manager := testManager(t)
	manager.now = func() time.Time { return time.Now().Add(-2 * time.Minute) }
	raw, _, err := manager.Sign(uuid.New(), uuid.New(), "jobpilot")
	if err != nil {
		t.Fatal(err)
	}
	manager.now = time.Now
	if _, err := manager.Parse(raw); err == nil {
		t.Fatal("expired token was accepted")
	}
}

func TestTamperedAndUnknownKeyTokensAreRejected(t *testing.T) {
	manager := testManager(t)
	raw, _, err := manager.Sign(uuid.New(), uuid.New(), "jobpilot")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	if _, err := manager.Parse(strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered token was accepted")
	}
	otherManager := testManager(t)
	if _, err := otherManager.Parse(raw); err == nil {
		t.Fatal("token signed with an unknown key was accepted")
	}
}
