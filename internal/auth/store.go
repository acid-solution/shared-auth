package auth

import (
	"context"
	"time"

	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/google/uuid"
)

type RateSnapshot struct {
	LastCreatedAt  *time.Time
	IdentifierHits int
	IPHits         int
}

type LoginRecord struct {
	User         domain.User
	PasswordHash string
}

type Store interface {
	Client(context.Context, string) (domain.Client, error)
	ReplaceClientOrigins(context.Context, string, []string) error
	VerificationRate(context.Context, string, string, []byte, time.Time) (RateSnapshot, error)
	CreateChallenge(context.Context, domain.Challenge) error
	InvalidateChallenge(context.Context, uuid.UUID, time.Time) error
	Challenge(context.Context, uuid.UUID) (domain.Challenge, error)
	IncrementChallengeAttempts(context.Context, uuid.UUID) (int, error)
	Register(context.Context, uuid.UUID, string, domain.Session) (domain.UserAccount, error)
	LoginRecord(context.Context, string) (LoginRecord, error)
	CreateSession(context.Context, domain.Session) error
	RotateSession(context.Context, uuid.UUID, string, []byte, []byte, time.Time) (uuid.UUID, time.Time, error)
	RevokeSession(context.Context, uuid.UUID, string, []byte, time.Time) (bool, error)
	Account(context.Context, uuid.UUID) (domain.UserAccount, error)
	PasswordHash(context.Context, uuid.UUID) (string, error)
	DeleteAccount(context.Context, uuid.UUID) error
	ResetPassword(context.Context, uuid.UUID, string, time.Time) (uuid.UUID, error)
	RecordEvent(context.Context, domain.Event) error
}
