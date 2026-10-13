package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/url"
	"strings"
	"time"

	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/google/uuid"
)

const RouteScope = "learning_route:import learning_route:read"

type ExchangeInput struct {
	SubjectToken  string
	Resource      string
	Scope         string
	ImportKey     string
	ContentDigest string
}

type ExchangeResult struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
}

// Session checks are separate from Store so existing consumers remain compatible.
type exchangeStore interface {
	ActiveExchangeSession(context.Context, uuid.UUID, uuid.UUID, string, time.Time) (bool, error)
}

func (s *Service) ConfigureExchange(secret, resource string) error {
	if secret == "" && resource == "" {
		return nil
	}
	u, err := url.Parse(resource)
	if len(secret) < 32 || err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return domain.ErrInvalidInput
	}
	s.exchangeSecret, s.exchangeResource = secret, resource
	return nil
}

func (s *Service) Exchange(ctx context.Context, clientID, secret string, input ExchangeInput) (ExchangeResult, error) {
	// Hashing gives constant-length comparison without leaking configured secret length.
	expected, actual := sha256.Sum256([]byte(s.exchangeSecret)), sha256.Sum256([]byte(secret))
	if s.exchangeSecret == "" || clientID != "jobpilot" || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		return ExchangeResult{}, domain.ErrUnauthorized
	}
	digest, err := hex.DecodeString(input.ContentDigest)
	if err != nil || len(digest) != 32 || input.ContentDigest != strings.ToLower(input.ContentDigest) || len(input.ImportKey) < 8 || len(input.ImportKey) > 200 || strings.TrimSpace(input.ImportKey) != input.ImportKey || input.Resource != s.exchangeResource || input.Scope != RouteScope {
		return ExchangeResult{}, domain.ErrInvalidInput
	}
	for _, c := range input.ImportKey {
		if c < 33 || c > 126 {
			return ExchangeResult{}, domain.ErrInvalidInput
		}
	}
	p, err := s.tokens.Parse(input.SubjectToken)
	if err != nil || p.ClientID != "jobpilot" {
		return ExchangeResult{}, domain.ErrUnauthorized
	}
	store, ok := s.store.(exchangeStore)
	if !ok {
		return ExchangeResult{}, domain.ErrUnauthorized
	}
	active, err := store.ActiveExchangeSession(ctx, p.UserID, p.SessionID, p.ClientID, s.now())
	if err != nil {
		return ExchangeResult{}, err
	}
	if !active {
		return ExchangeResult{}, domain.ErrUnauthorized
	}
	raw, expires, err := s.tokens.SignDelegation(p, input.Resource, input.Scope, input.ImportKey, input.ContentDigest)
	if err != nil {
		return ExchangeResult{}, domain.ErrUnauthorized
	}
	return ExchangeResult{AccessToken: raw, IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token", TokenType: "Bearer", ExpiresIn: int64(time.Until(expires).Seconds()), Scope: RouteScope}, nil
}
