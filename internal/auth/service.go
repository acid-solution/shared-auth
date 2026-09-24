package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/LeoninCS/shared-auth/internal/identity"
	"github.com/LeoninCS/shared-auth/internal/password"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/LeoninCS/shared-auth/internal/verification"
	"github.com/google/uuid"
)

type RequestMeta struct {
	Origin    string
	SourceIP  string
	UserAgent string
}

type VerificationInput struct {
	ClientID string
	Email    string
	Purpose  string
}

type VerificationResult struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	ResendAfter time.Time `json:"resend_after"`
}

type RegisterInput struct {
	ClientID    string
	ChallengeID uuid.UUID
	Code        string
	Password    string
}

type LoginInput struct {
	ClientID string
	Email    string
	Password string
}

type ChallengeInput struct {
	ClientID    string
	ChallengeID uuid.UUID
	Code        string
	Password    string
}

type IssueResult struct {
	Account      domain.UserAccount `json:"account"`
	AccessToken  string             `json:"access_token"`
	TokenType    string             `json:"token_type"`
	ExpiresAt    time.Time          `json:"expires_at"`
	RefreshToken string             `json:"-"`
	RefreshUntil time.Time          `json:"-"`
	Client       domain.Client      `json:"-"`
}

type RefreshResult struct {
	IssueResult
}

type Service struct {
	store           Store
	hasher          password.Hasher
	tokens          *token.Manager
	sender          verification.Sender
	hmacKey         []byte
	verificationTTL time.Duration
	refreshTTL      time.Duration
	now             func() time.Time
	dummyHash       string
}

func NewService(store Store, hasher password.Hasher, tokens *token.Manager, sender verification.Sender, hmacKey []byte, verificationTTL, refreshTTL time.Duration) (*Service, error) {
	dummyHash, err := hasher.Hash("shared-auth-dummy-password")
	if err != nil {
		return nil, err
	}
	return &Service{
		store: store, hasher: hasher, tokens: tokens, sender: sender,
		hmacKey: hmacKey, verificationTTL: verificationTTL, refreshTTL: refreshTTL,
		now: time.Now, dummyHash: dummyHash,
	}, nil
}

func (s *Service) Client(ctx context.Context, clientID, origin string) (domain.Client, error) {
	client, err := s.store.Client(ctx, strings.TrimSpace(clientID))
	if err != nil {
		return domain.Client{}, err
	}
	if !originAllowed(client, origin) {
		return domain.Client{}, domain.ErrForbidden
	}
	return client, nil
}

func (s *Service) RequestVerification(ctx context.Context, input VerificationInput, meta RequestMeta) (VerificationResult, error) {
	client, err := s.Client(ctx, input.ClientID, meta.Origin)
	if err != nil {
		return VerificationResult{}, err
	}
	if input.Purpose != domain.PurposeRegister && input.Purpose != domain.PurposeReset {
		return VerificationResult{}, domain.ErrInvalidInput
	}
	normalized, err := identity.NormalizeEmail(input.Email)
	if err != nil {
		return VerificationResult{}, err
	}
	now := s.now().UTC()
	ipHash := s.sensitiveMAC(meta.SourceIP)
	rate, err := s.store.VerificationRate(ctx, client.ID, normalized, ipHash, now.Add(-time.Hour))
	if err != nil {
		return VerificationResult{}, err
	}
	if rate.IdentifierHits >= 5 || rate.IPHits >= 20 || (rate.LastCreatedAt != nil && now.Sub(*rate.LastCreatedAt) < time.Minute) {
		return VerificationResult{}, domain.ErrRateLimited
	}
	code, err := randomCode()
	if err != nil {
		return VerificationResult{}, err
	}
	challengeID := uuid.New()
	expiresAt := now.Add(s.verificationTTL)
	challenge := domain.Challenge{
		ID: challengeID, ClientID: client.ID, Purpose: input.Purpose,
		Kind: domain.IdentityEmail, Identifier: normalized, IdentifierHash: s.sensitiveMAC(normalized),
		CodeMAC:     s.codeMAC(challengeID, code),
		MaxAttempts: 5, ExpiresAt: expiresAt, SourceIPHash: ipHash, CreatedAt: now,
	}
	if err := s.store.CreateChallenge(ctx, challenge); err != nil {
		return VerificationResult{}, err
	}
	if err := s.sender.Send(ctx, verification.Delivery{
		ChallengeID: challengeID, ClientID: client.ID, Identifier: normalized,
		Purpose: input.Purpose, Code: code, ExpiresAt: expiresAt, CreatedAt: now,
	}); err != nil {
		if invalidateErr := s.store.InvalidateChallenge(ctx, challengeID, now); invalidateErr != nil {
			slog.Warn("failed to invalidate undelivered verification challenge", "challenge_id", challengeID, "error", invalidateErr)
		}
		s.recordEvent(ctx, domain.Event{ClientID: client.ID, EventType: "verification_delivery", Outcome: "failed", Reason: "sender_error", IdentifierHash: challenge.IdentifierHash, SourceIPHash: ipHash, UserAgent: meta.UserAgent})
		return VerificationResult{}, err
	}
	s.recordEvent(ctx, domain.Event{ClientID: client.ID, EventType: "verification_requested", Outcome: "succeeded", IdentifierHash: challenge.IdentifierHash, SourceIPHash: ipHash, UserAgent: meta.UserAgent})
	return VerificationResult{ChallengeID: challengeID, ExpiresAt: expiresAt, ResendAfter: now.Add(time.Minute)}, nil
}

func (s *Service) Register(ctx context.Context, input RegisterInput, meta RequestMeta) (IssueResult, error) {
	client, err := s.Client(ctx, input.ClientID, meta.Origin)
	if err != nil {
		return IssueResult{}, err
	}
	if err := password.Validate(input.Password); err != nil {
		return IssueResult{}, domain.ErrInvalidInput
	}
	challenge, err := s.verifyChallenge(ctx, input.ChallengeID, input.Code, client.ID, domain.PurposeRegister)
	if err != nil {
		return IssueResult{}, err
	}
	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return IssueResult{}, err
	}
	now := s.now().UTC()
	userID := uuid.New()
	session, refreshToken, err := s.newSession(userID, client.ID, meta, now)
	if err != nil {
		return IssueResult{}, err
	}
	account, err := s.store.Register(ctx, challenge.ID, passwordHash, session)
	if err != nil {
		return IssueResult{}, err
	}
	result, err := s.issue(account, session, refreshToken, client)
	if err != nil {
		return IssueResult{}, err
	}
	s.recordEvent(ctx, eventFor(account.User.ID, client.ID, session.ID, "register", "succeeded", "", challenge.IdentifierHash, session.SourceIPHash, meta.UserAgent, now))
	return result, nil
}

func (s *Service) Login(ctx context.Context, input LoginInput, meta RequestMeta) (IssueResult, error) {
	client, err := s.Client(ctx, input.ClientID, meta.Origin)
	if err != nil {
		return IssueResult{}, err
	}
	normalized, err := identity.NormalizeEmail(input.Email)
	if err != nil {
		return IssueResult{}, domain.ErrInvalidCredentials
	}
	record, lookupErr := s.store.LoginRecord(ctx, normalized)
	hash := s.dummyHash
	if lookupErr == nil {
		hash = record.PasswordHash
	} else if !errors.Is(lookupErr, domain.ErrNotFound) {
		return IssueResult{}, lookupErr
	}
	valid := s.hasher.Compare(hash, input.Password)
	now := s.now().UTC()
	ipHash := s.sensitiveMAC(meta.SourceIP)
	identifierHash := s.sensitiveMAC(normalized)
	if !valid || lookupErr != nil || record.User.Status != "active" {
		s.recordEvent(ctx, domain.Event{ClientID: client.ID, EventType: "login", Outcome: "failed", Reason: "invalid_credentials", IdentifierHash: identifierHash, SourceIPHash: ipHash, UserAgent: meta.UserAgent, CreatedAt: now})
		return IssueResult{}, domain.ErrInvalidCredentials
	}
	session, refreshToken, err := s.newSession(record.User.ID, client.ID, meta, now)
	if err != nil {
		return IssueResult{}, err
	}
	if err := s.store.CreateSession(ctx, session); err != nil {
		return IssueResult{}, err
	}
	account, err := s.store.Account(ctx, record.User.ID)
	if err != nil {
		return IssueResult{}, err
	}
	result, err := s.issue(account, session, refreshToken, client)
	if err != nil {
		return IssueResult{}, err
	}
	s.recordEvent(ctx, eventFor(record.User.ID, client.ID, session.ID, "login", "succeeded", "", identifierHash, ipHash, meta.UserAgent, now))
	return result, nil
}

func (s *Service) Refresh(ctx context.Context, clientID, rawRefresh string, meta RequestMeta) (RefreshResult, error) {
	client, err := s.Client(ctx, clientID, meta.Origin)
	if err != nil {
		return RefreshResult{}, err
	}
	sessionID, secret, err := parseRefreshToken(rawRefresh)
	if err != nil {
		return RefreshResult{}, domain.ErrUnauthorized
	}
	newSecret, err := randomToken(32)
	if err != nil {
		return RefreshResult{}, err
	}
	now := s.now().UTC()
	userID, refreshUntil, err := s.store.RotateSession(ctx, sessionID, client.ID, tokenHash(secret), tokenHash(newSecret), now)
	if err != nil {
		s.recordEvent(ctx, domain.Event{ClientID: client.ID, SessionID: &sessionID, EventType: "refresh", Outcome: "failed", Reason: "invalid_or_reused", SourceIPHash: s.sensitiveMAC(meta.SourceIP), UserAgent: meta.UserAgent, CreatedAt: now})
		return RefreshResult{}, domain.ErrUnauthorized
	}
	account, err := s.store.Account(ctx, userID)
	if err != nil {
		return RefreshResult{}, err
	}
	session := domain.Session{ID: sessionID, UserID: userID, ClientID: client.ID, ExpiresAt: refreshUntil}
	result, err := s.issue(account, session, sessionID.String()+"."+newSecret, client)
	if err != nil {
		return RefreshResult{}, err
	}
	s.recordEvent(ctx, eventFor(userID, client.ID, sessionID, "refresh", "succeeded", "", nil, s.sensitiveMAC(meta.SourceIP), meta.UserAgent, now))
	return RefreshResult{IssueResult: result}, nil
}

func (s *Service) Logout(ctx context.Context, clientID, rawRefresh string, meta RequestMeta) (domain.Client, error) {
	client, err := s.Client(ctx, clientID, meta.Origin)
	if err != nil {
		return domain.Client{}, err
	}
	sessionID, secret, err := parseRefreshToken(rawRefresh)
	if err != nil {
		return client, nil
	}
	now := s.now().UTC()
	revoked, err := s.store.RevokeSession(ctx, sessionID, client.ID, tokenHash(secret), now)
	if err != nil {
		return domain.Client{}, err
	}
	outcome := "ignored"
	if revoked {
		outcome = "succeeded"
	}
	s.recordEvent(ctx, domain.Event{ClientID: client.ID, SessionID: &sessionID, EventType: "logout", Outcome: outcome, SourceIPHash: s.sensitiveMAC(meta.SourceIP), UserAgent: meta.UserAgent, CreatedAt: now})
	return client, nil
}

func (s *Service) Account(ctx context.Context, principal token.Principal) (domain.UserAccount, error) {
	account, err := s.store.Account(ctx, principal.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.UserAccount{}, domain.ErrUnauthorized
	}
	return account, err
}

func (s *Service) DeleteAccount(ctx context.Context, principal token.Principal, currentPassword string, meta RequestMeta) (domain.Client, error) {
	client, err := s.Client(ctx, principal.ClientID, meta.Origin)
	if err != nil {
		return domain.Client{}, err
	}
	passwordHash, err := s.store.PasswordHash(ctx, principal.UserID)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.Client{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.Client{}, err
	}
	if !s.hasher.Compare(passwordHash, currentPassword) {
		s.recordEvent(ctx, eventFor(principal.UserID, client.ID, principal.SessionID, "account_delete", "failed", "invalid_password", nil, s.sensitiveMAC(meta.SourceIP), meta.UserAgent, s.now().UTC()))
		return domain.Client{}, domain.ErrPasswordMismatch
	}
	now := s.now().UTC()
	if err := s.store.DeleteAccount(ctx, principal.UserID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Client{}, domain.ErrUnauthorized
		}
		return domain.Client{}, err
	}
	s.recordEvent(ctx, eventFor(principal.UserID, client.ID, principal.SessionID, "account_delete", "succeeded", "", nil, s.sensitiveMAC(meta.SourceIP), meta.UserAgent, now))
	return client, nil
}

func (s *Service) ResetPassword(ctx context.Context, input ChallengeInput, meta RequestMeta) error {
	client, err := s.Client(ctx, input.ClientID, meta.Origin)
	if err != nil {
		return err
	}
	if err := password.Validate(input.Password); err != nil {
		return domain.ErrInvalidInput
	}
	challenge, err := s.verifyChallenge(ctx, input.ChallengeID, input.Code, client.ID, domain.PurposeReset)
	if err != nil {
		return err
	}
	passwordHash, err := s.hasher.Hash(input.Password)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	userID, err := s.store.ResetPassword(ctx, challenge.ID, passwordHash, now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrVerificationFailed
		}
		return err
	}
	s.recordEvent(ctx, domain.Event{UserID: &userID, ClientID: client.ID, EventType: "password_reset", Outcome: "succeeded", IdentifierHash: challenge.IdentifierHash, SourceIPHash: s.sensitiveMAC(meta.SourceIP), UserAgent: meta.UserAgent, CreatedAt: now})
	return nil
}

func (s *Service) ParseAccessToken(raw string) (token.Principal, error) {
	return s.tokens.Parse(raw)
}

func (s *Service) JWKS() token.JWKS {
	return s.tokens.JWKS()
}

func (s *Service) verifyChallenge(ctx context.Context, id uuid.UUID, code, clientID, purpose string) (domain.Challenge, error) {
	challenge, err := s.store.Challenge(ctx, id)
	if err != nil {
		return domain.Challenge{}, domain.ErrVerificationFailed
	}
	now := s.now().UTC()
	if challenge.ClientID != clientID || challenge.Purpose != purpose ||
		challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) || challenge.Attempts >= challenge.MaxAttempts {
		return domain.Challenge{}, domain.ErrVerificationFailed
	}
	if !hmac.Equal(challenge.CodeMAC, s.codeMAC(challenge.ID, strings.TrimSpace(code))) {
		_, _ = s.store.IncrementChallengeAttempts(ctx, challenge.ID)
		return domain.Challenge{}, domain.ErrVerificationFailed
	}
	return challenge, nil
}

func (s *Service) newSession(userID uuid.UUID, clientID string, meta RequestMeta, now time.Time) (domain.Session, string, error) {
	secret, err := randomToken(32)
	if err != nil {
		return domain.Session{}, "", err
	}
	sessionID := uuid.New()
	return domain.Session{
		ID: sessionID, UserID: userID, ClientID: clientID,
		RefreshTokenHash: tokenHash(secret), ExpiresAt: now.Add(s.refreshTTL), LastUsedAt: now,
		UserAgent: truncate(meta.UserAgent, 512), SourceIPHash: s.sensitiveMAC(meta.SourceIP),
		CreatedAt: now, UpdatedAt: now,
	}, sessionID.String() + "." + secret, nil
}

func (s *Service) issue(account domain.UserAccount, session domain.Session, refreshToken string, client domain.Client) (IssueResult, error) {
	accessToken, expiresAt, err := s.tokens.Sign(account.User.ID, session.ID, client.Audience)
	if err != nil {
		return IssueResult{}, err
	}
	return IssueResult{
		Account: account, AccessToken: accessToken, TokenType: "Bearer", ExpiresAt: expiresAt,
		RefreshToken: refreshToken, RefreshUntil: session.ExpiresAt, Client: client,
	}, nil
}

func (s *Service) codeMAC(challengeID uuid.UUID, code string) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(challengeID.String()))
	mac.Write([]byte{'|'})
	mac.Write([]byte(code))
	return mac.Sum(nil)
}

func (s *Service) sensitiveMAC(value string) []byte {
	mac := hmac.New(sha256.New, s.hmacKey)
	mac.Write([]byte(value))
	return mac.Sum(nil)
}

func (s *Service) recordEvent(ctx context.Context, event domain.Event) {
	if event.ID == uuid.Nil {
		event.ID = uuid.New()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = s.now().UTC()
	}
	if err := s.store.RecordEvent(ctx, event); err != nil {
		slog.Warn("failed to record auth event", "event_type", event.EventType, "error", err)
	}
}

func originAllowed(client domain.Client, origin string) bool {
	if origin == "" {
		return true
	}
	for _, allowed := range client.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func randomCode() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", value.Int64()), nil
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func parseRefreshToken(raw string) (uuid.UUID, string, error) {
	idValue, secret, ok := strings.Cut(raw, ".")
	if !ok || len(secret) < 40 {
		return uuid.Nil, "", domain.ErrUnauthorized
	}
	id, err := uuid.Parse(idValue)
	if err != nil {
		return uuid.Nil, "", domain.ErrUnauthorized
	}
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 32 {
		return uuid.Nil, "", domain.ErrUnauthorized
	}
	return id, secret, nil
}

func tokenHash(secret string) []byte {
	hash := sha256.Sum256([]byte(secret))
	return hash[:]
}

func eventFor(userID uuid.UUID, clientID string, sessionID uuid.UUID, eventType, outcome, reason string, identifierHash, ipHash []byte, userAgent string, now time.Time) domain.Event {
	return domain.Event{ID: uuid.New(), UserID: &userID, ClientID: clientID, SessionID: &sessionID, EventType: eventType, Outcome: outcome, Reason: reason, IdentifierHash: identifierHash, SourceIPHash: ipHash, UserAgent: truncate(userAgent, 512), CreatedAt: now}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
