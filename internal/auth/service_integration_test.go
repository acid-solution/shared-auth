package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/LeoninCS/shared-auth/internal/password"
	"github.com/LeoninCS/shared-auth/internal/storage/postgres"
	"github.com/LeoninCS/shared-auth/internal/storage/postgres/migrations"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/LeoninCS/shared-auth/internal/verification"
	"github.com/pressly/goose/v3"
)

func TestCompleteAccountLifecycle(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	database, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.Exec(`DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
		t.Fatal(err)
	}
	goose.SetBaseFS(migrations.Files)
	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatal(err)
	}
	if err := goose.Up(database, "sql"); err != nil {
		t.Fatal(err)
	}

	repository := postgres.NewRepository(database)
	manager := integrationTokenManager(t)
	outbox := verification.NewDevOutbox()
	service, err := auth.NewService(repository, password.NewHasher(4), manager, outbox, []byte("0123456789abcdef0123456789abcdef"), 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	meta := auth.RequestMeta{SourceIP: "127.0.0.1", UserAgent: "integration-test"}
	failureService, err := auth.NewService(repository, password.NewHasher(4), manager, failedSender{}, []byte("0123456789abcdef0123456789abcdef"), 10*time.Minute, 7*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failureService.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "undelivered@example.com", Purpose: domain.PurposeRegister,
	}, auth.RequestMeta{SourceIP: "127.0.0.2", UserAgent: "integration-test"}); !errors.Is(err, verification.ErrDeliveryFailed) {
		t.Fatalf("expected delivery failure, got %v", err)
	}
	var undeliveredChallengeActive bool
	if err := database.QueryRow(`
		SELECT EXISTS(
			SELECT 1 FROM verification_challenges
			WHERE normalized_identifier='undelivered@example.com' AND consumed_at IS NULL
		)`).Scan(&undeliveredChallengeActive); err != nil {
		t.Fatal(err)
	}
	if undeliveredChallengeActive {
		t.Fatal("undelivered verification challenge remained active")
	}

	registerChallenge, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "Person@Example.com", Purpose: domain.PurposeRegister,
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	registerCode := outbox.List("person@example.com")[0].Code
	registered, err := service.Register(ctx, auth.RegisterInput{
		ClientID: "jobpilot", ChallengeID: registerChallenge.ChallengeID,
		Code: registerCode, Password: "first-password",
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.Account.Identities) != 1 || registered.Account.Identities[0].Value != "person@example.com" {
		t.Fatalf("unexpected registered account: %+v", registered.Account)
	}
	t.Run("route delegation checks live session", func(t *testing.T) {
		secret := "route-exchange-test-secret-32-characters"
		resource := "http://127.0.0.1:8081/mcp"
		if err := service.ConfigureExchange(secret, resource); err != nil {
			t.Fatal(err)
		}
		input := auth.ExchangeInput{SubjectToken: registered.AccessToken, Resource: resource, Scope: auth.RouteScope, ImportKey: "route-test-request", ContentDigest: strings.Repeat("a", 64)}
		if _, err := service.Exchange(ctx, "jobpilot", secret, input); err != nil {
			t.Fatal(err)
		}
		p, err := manager.Parse(registered.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE sessions SET revoked_at=now() WHERE id=$1`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Exchange(ctx, "jobpilot", secret, input); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal("revoked session accepted", err)
		}
		if _, err := database.Exec(`UPDATE sessions SET revoked_at=NULL WHERE id=$1`, p.SessionID); err != nil {
			t.Fatal(err)
		}
		if _, err := database.Exec(`UPDATE users SET status='disabled' WHERE id=$1`, p.UserID); err != nil {
			t.Fatal(err)
		}
		if _, err := service.Exchange(ctx, "jobpilot", secret, input); !errors.Is(err, domain.ErrUnauthorized) {
			t.Fatal("disabled account accepted", err)
		}
		if _, err := database.Exec(`UPDATE users SET status='active' WHERE id=$1`, p.UserID); err != nil {
			t.Fatal(err)
		}
	})
	var legacyOwnerColumns int
	if err := database.QueryRow(`
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema='public' AND table_name='verification_challenges' AND column_name='owner_user_id'`).Scan(&legacyOwnerColumns); err != nil {
		t.Fatal(err)
	}
	if legacyOwnerColumns != 0 {
		t.Fatal("legacy identity binding column still exists")
	}
	if _, err := service.Register(ctx, auth.RegisterInput{
		ClientID: "jobpilot", ChallengeID: registerChallenge.ChallengeID,
		Code: registerCode, Password: "first-password",
	}, meta); !errors.Is(err, domain.ErrVerificationFailed) {
		t.Fatalf("reused verification challenge returned %v", err)
	}

	rateChallenge, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "rate@example.com", Purpose: domain.PurposeRegister,
	}, meta)
	if err != nil || rateChallenge.ChallengeID.String() == "" {
		t.Fatalf("first rate-limited target request failed: %v", err)
	}
	if _, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "rate@example.com", Purpose: domain.PurposeRegister,
	}, meta); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("immediate resend returned %v", err)
	}

	attemptChallenge, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "attempts@example.com", Purpose: domain.PurposeRegister,
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	attemptCode := outbox.List("attempts@example.com")[0].Code
	wrongCode := "000000"
	if attemptCode == wrongCode {
		wrongCode = "000001"
	}
	for range 5 {
		if _, err := service.Register(ctx, auth.RegisterInput{
			ClientID: "jobpilot", ChallengeID: attemptChallenge.ChallengeID,
			Code: wrongCode, Password: "first-password",
		}, meta); !errors.Is(err, domain.ErrVerificationFailed) {
			t.Fatalf("wrong verification code returned %v", err)
		}
	}
	if _, err := service.Register(ctx, auth.RegisterInput{
		ClientID: "jobpilot", ChallengeID: attemptChallenge.ChallengeID,
		Code: attemptCode, Password: "first-password",
	}, meta); !errors.Is(err, domain.ErrVerificationFailed) {
		t.Fatalf("challenge accepted after five failures: %v", err)
	}

	expiredChallenge, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "jobpilot", Email: "expired@example.com", Purpose: domain.PurposeRegister,
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	expiredCode := outbox.List("expired@example.com")[0].Code
	if _, err := database.Exec(`UPDATE verification_challenges SET expires_at=now()-interval '1 minute' WHERE id=$1`, expiredChallenge.ChallengeID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Register(ctx, auth.RegisterInput{
		ClientID: "jobpilot", ChallengeID: expiredChallenge.ChallengeID,
		Code: expiredCode, Password: "first-password",
	}, meta); !errors.Is(err, domain.ErrVerificationFailed) {
		t.Fatalf("expired challenge returned %v", err)
	}

	emailLogin, err := service.Login(ctx, auth.LoginInput{
		ClientID: "jobpilot", Email: "person@example.com", Password: "first-password",
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if emailLogin.Account.User.ID != registered.Account.User.ID {
		t.Fatalf("email login resolved to another user: %s != %s", emailLogin.Account.User.ID, registered.Account.User.ID)
	}
	if _, err := service.Refresh(ctx, "studyflow", emailLogin.RefreshToken, meta); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("cross-client refresh returned %v", err)
	}
	refreshed, err := service.Refresh(ctx, "jobpilot", emailLogin.RefreshToken, meta)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.RefreshToken == emailLogin.RefreshToken {
		t.Fatal("refresh token was not rotated")
	}
	if _, err := service.Refresh(ctx, "jobpilot", emailLogin.RefreshToken, meta); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("reused refresh token returned %v", err)
	}

	resetChallenge, err := service.RequestVerification(ctx, auth.VerificationInput{
		ClientID: "studyflow", Email: "person@example.com", Purpose: domain.PurposeReset,
	}, meta)
	if err != nil {
		t.Fatal(err)
	}
	resetCode := outbox.List("person@example.com")[0].Code
	if err := service.ResetPassword(ctx, auth.ChallengeInput{
		ClientID: "studyflow", ChallengeID: resetChallenge.ChallengeID,
		Code: resetCode, Password: "second-password",
	}, meta); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Refresh(ctx, "jobpilot", refreshed.RefreshToken, meta); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("session survived password reset: %v", err)
	}
	if _, err := service.Login(ctx, auth.LoginInput{ClientID: "studyflow", Email: "person@example.com", Password: "first-password"}, meta); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("old password returned %v", err)
	}
	finalLogin, err := service.Login(ctx, auth.LoginInput{ClientID: "studyflow", Email: "person@example.com", Password: "second-password"}, meta)
	if err != nil {
		t.Fatal(err)
	}
	if finalLogin.Account.User.ID != registered.Account.User.ID {
		t.Fatal("password reset changed the stable user ID")
	}

	var rawCodeFound, rawRefreshFound bool
	if err := database.QueryRow(`SELECT EXISTS(SELECT 1 FROM verification_challenges WHERE encode(code_mac, 'escape') = $1)`, resetCode).Scan(&rawCodeFound); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT EXISTS(SELECT 1 FROM sessions WHERE encode(refresh_token_hash, 'escape') = $1)`, finalLogin.RefreshToken).Scan(&rawRefreshFound); err != nil {
		t.Fatal(err)
	}
	if rawCodeFound || rawRefreshFound {
		t.Fatal("a raw secret was persisted")
	}
	principal, err := service.ParseAccessToken(finalLogin.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.DeleteAccount(ctx, principal, "wrong-password", meta); !errors.Is(err, domain.ErrPasswordMismatch) {
		t.Fatalf("wrong deletion password returned %v", err)
	}
	if _, err := service.Account(ctx, principal); err != nil {
		t.Fatalf("account disappeared after rejected deletion: %v", err)
	}
	if _, err := service.DeleteAccount(ctx, principal, "second-password", meta); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Account(ctx, principal); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("deleted account remained accessible: %v", err)
	}
	if _, err := service.Login(ctx, auth.LoginInput{ClientID: "studyflow", Email: "person@example.com", Password: "second-password"}, meta); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("deleted account could still log in: %v", err)
	}
	var users, identities, sessions, successfulDeleteEvents int
	if err := database.QueryRow(`SELECT count(*) FROM users WHERE id=$1`, registered.Account.User.ID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM user_identities WHERE user_id=$1`, registered.Account.User.ID).Scan(&identities); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM sessions WHERE user_id=$1`, registered.Account.User.ID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT count(*) FROM auth_events WHERE user_id=$1 AND event_type='account_delete' AND outcome='succeeded'`, registered.Account.User.ID).Scan(&successfulDeleteEvents); err != nil {
		t.Fatal(err)
	}
	if users != 0 || identities != 0 || sessions != 0 || successfulDeleteEvents != 1 {
		t.Fatalf("unexpected deletion state: users=%d identities=%d sessions=%d events=%d", users, identities, sessions, successfulDeleteEvents)
	}
}

type failedSender struct{}

func (failedSender) Send(context.Context, verification.Delivery) error {
	return verification.ErrDeliveryFailed
}

func integrationTokenManager(t *testing.T) *token.Manager {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := token.NewManagerPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), "integration-key", "shared-auth", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}
