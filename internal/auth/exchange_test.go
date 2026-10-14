package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/google/uuid"
	"strings"
	"testing"
	"time"
)

type exchangeFakeStore struct {
	Store
	active  bool
	checked bool
}

func TestExchangeHTTPRequiresExplicitOptIn(t *testing.T) {
	s := &Service{}
	secret := strings.Repeat("s", 32)
	resource := "http://192.0.2.1:18084/mcp"
	if s.ConfigureExchange(secret, resource) == nil || s.ConfigureExchange(secret, resource, false) == nil {
		t.Fatal("HTTP accepted without opt-in")
	}
	if err := s.ConfigureExchange(secret, resource, true); err != nil {
		t.Fatal("explicit HTTP rejected", err)
	}
	for _, raw := range []string{"http://user:secret@example.com/mcp", "http://example.com/mcp?key=x", "http://example.com/mcp#fragment", "ftp://example.com/mcp", "http://:80/mcp"} {
		if s.ConfigureExchange(secret, raw, true) == nil {
			t.Fatal("URL structure checks bypassed", raw)
		}
	}
}

func (f *exchangeFakeStore) ActiveExchangeSession(context.Context, uuid.UUID, uuid.UUID, string, time.Time) (bool, error) {
	f.checked = true
	return f.active, nil
}

func TestExchangeSecurityBoundary(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	manager, err := token.NewManagerPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), "key", "shared-auth", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	store := &exchangeFakeStore{active: true}
	s := &Service{tokens: manager, store: store, now: time.Now}
	secret := strings.Repeat("s", 32)
	resource := "http://127.0.0.1:8081/mcp"
	if err := s.ConfigureExchange(secret, resource); err != nil {
		t.Fatal(err)
	}
	raw, _, _ := manager.Sign(uuid.New(), uuid.New(), "jobpilot")
	input := ExchangeInput{SubjectToken: raw, Resource: resource, Scope: RouteScope, ImportKey: "request-123", ContentDigest: strings.Repeat("a", 64)}
	result, err := s.Exchange(context.Background(), "jobpilot", secret, input)
	if err != nil || result.AccessToken == "" || !store.checked || result.ExpiresIn > 120 {
		t.Fatal("valid exchange failed", err)
	}
	for _, change := range []func(*ExchangeInput){func(i *ExchangeInput) { i.Resource = "https://attacker.example/mcp" }, func(i *ExchangeInput) { i.Scope = "*" }, func(i *ExchangeInput) { i.ContentDigest = "not-a-digest" }} {
		copy := input
		change(&copy)
		if _, err := s.Exchange(context.Background(), "jobpilot", secret, copy); !errors.Is(err, domain.ErrInvalidInput) {
			t.Fatal("invalid request accepted", err)
		}
	}
	if _, err := s.Exchange(context.Background(), "jobpilot", "wrong", input); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("wrong service accepted")
	}
	store.active = false
	if _, err := s.Exchange(context.Background(), "jobpilot", secret, input); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("revoked account/session accepted")
	}
	raw, _, _ = manager.Sign(uuid.New(), uuid.New(), "studyflow")
	input.SubjectToken = raw
	if _, err := s.Exchange(context.Background(), "jobpilot", secret, input); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatal("wrong source audience accepted")
	}
}
