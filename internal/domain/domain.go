package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound           = errors.New("not found")
	ErrInvalidInput       = errors.New("invalid input")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrPasswordMismatch   = errors.New("password mismatch")
	ErrVerificationFailed = errors.New("verification failed")
	ErrIdentityExists     = errors.New("identity already exists")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrRateLimited        = errors.New("rate limited")
	ErrClientNotFound     = errors.New("client not found")
)

const (
	IdentityEmail = "email"

	PurposeRegister = "register"
	PurposeReset    = "reset"
)

type Client struct {
	ID             string
	Audience       string
	CookieName     string
	AllowedOrigins []string
	Enabled        bool
}

type User struct {
	ID        uuid.UUID `json:"id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Identity struct {
	ID         uuid.UUID `json:"id"`
	UserID     uuid.UUID `json:"-"`
	Kind       string    `json:"kind"`
	Value      string    `json:"value"`
	VerifiedAt time.Time `json:"verified_at"`
	CreatedAt  time.Time `json:"created_at"`
}

type UserAccount struct {
	User       User       `json:"user"`
	Identities []Identity `json:"identities"`
}

type Challenge struct {
	ID             uuid.UUID
	ClientID       string
	Purpose        string
	Kind           string
	Identifier     string
	IdentifierHash []byte
	CodeMAC        []byte
	Attempts       int
	MaxAttempts    int
	ExpiresAt      time.Time
	ConsumedAt     *time.Time
	SourceIPHash   []byte
	CreatedAt      time.Time
}

type Session struct {
	ID               uuid.UUID
	UserID           uuid.UUID
	ClientID         string
	RefreshTokenHash []byte
	ExpiresAt        time.Time
	LastUsedAt       time.Time
	RevokedAt        *time.Time
	UserAgent        string
	SourceIPHash     []byte
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type Event struct {
	ID             uuid.UUID
	UserID         *uuid.UUID
	ClientID       string
	SessionID      *uuid.UUID
	EventType      string
	Outcome        string
	Reason         string
	IdentifierHash []byte
	SourceIPHash   []byte
	UserAgent      string
	CreatedAt      time.Time
}
