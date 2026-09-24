package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

type Repository struct {
	database *sql.DB
}

func NewRepository(database *sql.DB) *Repository {
	return &Repository{database: database}
}

func (r *Repository) Client(ctx context.Context, id string) (domain.Client, error) {
	var client domain.Client
	var originsJSON string
	err := r.database.QueryRowContext(ctx, `
		SELECT id, audience, refresh_cookie_name, to_json(allowed_origins)::text, enabled
		FROM auth_clients WHERE id = $1`, id).Scan(
		&client.ID, &client.Audience, &client.CookieName, &originsJSON, &client.Enabled,
	)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !client.Enabled) {
		return domain.Client{}, domain.ErrClientNotFound
	}
	if err != nil {
		return domain.Client{}, err
	}
	if err := json.Unmarshal([]byte(originsJSON), &client.AllowedOrigins); err != nil {
		return domain.Client{}, err
	}
	return client, nil
}

func (r *Repository) ReplaceClientOrigins(ctx context.Context, id string, origins []string) error {
	result, err := r.database.ExecContext(ctx, `
		UPDATE auth_clients SET allowed_origins = string_to_array($2, ','), updated_at = now() WHERE id = $1`, id, strings.Join(origins, ","))
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrClientNotFound
	}
	return nil
}

func (r *Repository) VerificationRate(ctx context.Context, clientID, identifier string, ipHash []byte, since time.Time) (auth.RateSnapshot, error) {
	var snapshot auth.RateSnapshot
	var last sql.NullTime
	err := r.database.QueryRowContext(ctx, `
		SELECT max(created_at), count(*)
		FROM verification_challenges
		WHERE client_id = $1 AND kind = 'email' AND normalized_identifier = $2 AND created_at >= $3`,
		clientID, identifier, since,
	).Scan(&last, &snapshot.IdentifierHits)
	if err != nil {
		return snapshot, err
	}
	if last.Valid {
		snapshot.LastCreatedAt = &last.Time
	}
	err = r.database.QueryRowContext(ctx, `
		SELECT count(*) FROM verification_challenges
		WHERE source_ip_hash = $1 AND created_at >= $2`, ipHash, since,
	).Scan(&snapshot.IPHits)
	return snapshot, err
}

func (r *Repository) CreateChallenge(ctx context.Context, challenge domain.Challenge) error {
	_, err := r.database.ExecContext(ctx, `
		INSERT INTO verification_challenges (
			id, client_id, purpose, kind, normalized_identifier, identifier_hash,
			code_mac, attempts, max_attempts, expires_at,
			source_ip_hash, created_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		challenge.ID, challenge.ClientID, challenge.Purpose, challenge.Kind,
		challenge.Identifier, challenge.IdentifierHash, challenge.CodeMAC,
		challenge.Attempts, challenge.MaxAttempts,
		challenge.ExpiresAt, challenge.SourceIPHash, challenge.CreatedAt,
	)
	return err
}

func (r *Repository) InvalidateChallenge(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := r.database.ExecContext(ctx, `
		UPDATE verification_challenges SET consumed_at = $2
		WHERE id = $1 AND consumed_at IS NULL`, id, at)
	return err
}

func (r *Repository) Challenge(ctx context.Context, id uuid.UUID) (domain.Challenge, error) {
	var challenge domain.Challenge
	var consumedAt sql.NullTime
	err := r.database.QueryRowContext(ctx, `
		SELECT id, client_id, purpose, kind, normalized_identifier, identifier_hash,
			code_mac, attempts, max_attempts, expires_at,
			consumed_at, source_ip_hash, created_at
		FROM verification_challenges WHERE id = $1`, id).Scan(
		&challenge.ID, &challenge.ClientID, &challenge.Purpose, &challenge.Kind,
		&challenge.Identifier, &challenge.IdentifierHash, &challenge.CodeMAC,
		&challenge.Attempts, &challenge.MaxAttempts,
		&challenge.ExpiresAt, &consumedAt, &challenge.SourceIPHash, &challenge.CreatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Challenge{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Challenge{}, err
	}
	if consumedAt.Valid {
		challenge.ConsumedAt = &consumedAt.Time
	}
	return challenge, nil
}

func (r *Repository) IncrementChallengeAttempts(ctx context.Context, id uuid.UUID) (int, error) {
	var attempts int
	err := r.database.QueryRowContext(ctx, `
		UPDATE verification_challenges SET attempts = attempts + 1
		WHERE id = $1 AND consumed_at IS NULL AND attempts < max_attempts
		RETURNING attempts`, id).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, domain.ErrVerificationFailed
	}
	return attempts, err
}

func (r *Repository) Register(ctx context.Context, challengeID uuid.UUID, passwordHash string, session domain.Session) (domain.UserAccount, error) {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return domain.UserAccount{}, err
	}
	defer tx.Rollback()
	var kind, identifier string
	var verifiedAt time.Time
	err = tx.QueryRowContext(ctx, `
		UPDATE verification_challenges SET consumed_at = now()
		WHERE id = $1 AND purpose = 'register' AND consumed_at IS NULL
			AND attempts < max_attempts AND expires_at > now()
		RETURNING kind, normalized_identifier, consumed_at`, challengeID).Scan(&kind, &identifier, &verifiedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.UserAccount{}, domain.ErrVerificationFailed
	}
	if err != nil {
		return domain.UserAccount{}, err
	}
	user := domain.User{ID: session.UserID, Status: "active", CreatedAt: verifiedAt, UpdatedAt: verifiedAt}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO users (id, password_hash, status, created_at, updated_at)
		VALUES ($1,$2,'active',$3,$3)`, user.ID, passwordHash, verifiedAt); err != nil {
		return domain.UserAccount{}, mapConstraintError(err)
	}
	identity := domain.Identity{ID: uuid.New(), UserID: user.ID, Kind: kind, Value: identifier, VerifiedAt: verifiedAt, CreatedAt: verifiedAt}
	if _, err = tx.ExecContext(ctx, `
		INSERT INTO user_identities (id,user_id,kind,normalized_value,verified_at,created_at)
		VALUES ($1,$2,$3,$4,$5,$5)`, identity.ID, user.ID, kind, identifier, verifiedAt); err != nil {
		return domain.UserAccount{}, mapConstraintError(err)
	}
	if err = insertSession(ctx, tx, session); err != nil {
		return domain.UserAccount{}, err
	}
	if err = tx.Commit(); err != nil {
		return domain.UserAccount{}, err
	}
	return domain.UserAccount{User: user, Identities: []domain.Identity{identity}}, nil
}

func (r *Repository) LoginRecord(ctx context.Context, email string) (auth.LoginRecord, error) {
	var record auth.LoginRecord
	err := r.database.QueryRowContext(ctx, `
		SELECT u.id, u.status, u.created_at, u.updated_at, u.password_hash
		FROM users u JOIN user_identities i ON i.user_id = u.id
		WHERE i.kind = 'email' AND i.normalized_value = $1`, email).Scan(
		&record.User.ID, &record.User.Status, &record.User.CreatedAt,
		&record.User.UpdatedAt, &record.PasswordHash,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.LoginRecord{}, domain.ErrNotFound
	}
	return record, err
}

func (r *Repository) CreateSession(ctx context.Context, session domain.Session) error {
	return insertSession(ctx, r.database, session)
}

type sqlExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertSession(ctx context.Context, executor sqlExecutor, session domain.Session) error {
	_, err := executor.ExecContext(ctx, `
		INSERT INTO sessions (
			id,user_id,client_id,refresh_token_hash,expires_at,last_used_at,
			user_agent,source_ip_hash,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		session.ID, session.UserID, session.ClientID, session.RefreshTokenHash,
		session.ExpiresAt, session.LastUsedAt, session.UserAgent,
		session.SourceIPHash, session.CreatedAt, session.UpdatedAt,
	)
	return err
}

func (r *Repository) RotateSession(ctx context.Context, id uuid.UUID, clientID string, oldHash, newHash []byte, now time.Time) (uuid.UUID, time.Time, error) {
	var userID uuid.UUID
	var expiresAt time.Time
	err := r.database.QueryRowContext(ctx, `
		UPDATE sessions SET refresh_token_hash = $4, last_used_at = $5, updated_at = $5
		WHERE id = $1 AND client_id = $2 AND refresh_token_hash = $3
			AND revoked_at IS NULL AND expires_at > $5
		RETURNING user_id, expires_at`, id, clientID, oldHash, newHash, now).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, time.Time{}, domain.ErrUnauthorized
	}
	return userID, expiresAt, err
}

func (r *Repository) RevokeSession(ctx context.Context, id uuid.UUID, clientID string, refreshHash []byte, now time.Time) (bool, error) {
	result, err := r.database.ExecContext(ctx, `
		UPDATE sessions SET revoked_at = $4, updated_at = $4
		WHERE id = $1 AND client_id = $2 AND refresh_token_hash = $3 AND revoked_at IS NULL`,
		id, clientID, refreshHash, now)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	return rows > 0, err
}

func (r *Repository) Account(ctx context.Context, userID uuid.UUID) (domain.UserAccount, error) {
	var account domain.UserAccount
	err := r.database.QueryRowContext(ctx, `
		SELECT id,status,created_at,updated_at FROM users WHERE id=$1`, userID).Scan(
		&account.User.ID, &account.User.Status, &account.User.CreatedAt, &account.User.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.UserAccount{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.UserAccount{}, err
	}
	rows, err := r.database.QueryContext(ctx, `
		SELECT id,user_id,kind,normalized_value,verified_at,created_at
		FROM user_identities WHERE user_id=$1 ORDER BY kind`, userID)
	if err != nil {
		return domain.UserAccount{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var identity domain.Identity
		if err := rows.Scan(&identity.ID, &identity.UserID, &identity.Kind, &identity.Value, &identity.VerifiedAt, &identity.CreatedAt); err != nil {
			return domain.UserAccount{}, err
		}
		account.Identities = append(account.Identities, identity)
	}
	return account, rows.Err()
}

func (r *Repository) PasswordHash(ctx context.Context, userID uuid.UUID) (string, error) {
	var passwordHash string
	err := r.database.QueryRowContext(ctx, `
		SELECT password_hash FROM users WHERE id=$1 AND status='active'`, userID).Scan(&passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", domain.ErrNotFound
	}
	return passwordHash, err
}

func (r *Repository) DeleteAccount(ctx context.Context, userID uuid.UUID) error {
	result, err := r.database.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return domain.ErrNotFound
	}
	return nil
}

func (r *Repository) ResetPassword(ctx context.Context, challengeID uuid.UUID, passwordHash string, now time.Time) (uuid.UUID, error) {
	tx, err := r.database.BeginTx(ctx, nil)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback()
	var kind, identifier string
	err = tx.QueryRowContext(ctx, `
		UPDATE verification_challenges SET consumed_at=$2
		WHERE id=$1 AND purpose='reset' AND consumed_at IS NULL
			AND attempts < max_attempts AND expires_at > $2
		RETURNING kind, normalized_identifier`, challengeID, now).Scan(&kind, &identifier)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, domain.ErrVerificationFailed
	}
	if err != nil {
		return uuid.Nil, err
	}
	var userID uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT user_id FROM user_identities WHERE kind=$1 AND normalized_value=$2`, kind, identifier).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, domain.ErrVerificationFailed
	}
	if err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET password_hash=$2, updated_at=$3 WHERE id=$1`, userID, passwordHash, now); err != nil {
		return uuid.Nil, err
	}
	if _, err = tx.ExecContext(ctx, `
		UPDATE sessions SET revoked_at=$2, updated_at=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, now); err != nil {
		return uuid.Nil, err
	}
	if err = tx.Commit(); err != nil {
		return uuid.Nil, err
	}
	return userID, nil
}

func (r *Repository) RecordEvent(ctx context.Context, event domain.Event) error {
	_, err := r.database.ExecContext(ctx, `
		INSERT INTO auth_events (
			id,user_id,client_id,session_id,event_type,outcome,reason,
			identifier_hash,source_ip_hash,user_agent,created_at
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11)`,
		event.ID, event.UserID, event.ClientID, event.SessionID, event.EventType,
		event.Outcome, event.Reason, event.IdentifierHash, event.SourceIPHash,
		event.UserAgent, event.CreatedAt,
	)
	return err
}

func mapConstraintError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return domain.ErrIdentityExists
	}
	return err
}
