-- +goose Up
-- Remove unsupported identity data left by pre-release schemas, then enforce
-- the email-only public contract for upgraded databases.
DELETE FROM verification_challenges
WHERE kind <> 'email' OR purpose NOT IN ('register', 'reset');
DELETE FROM user_identities WHERE kind <> 'email';
DELETE FROM users u WHERE NOT EXISTS (
    SELECT 1 FROM user_identities i WHERE i.user_id = u.id
);

ALTER TABLE verification_challenges DROP COLUMN IF EXISTS owner_user_id;

ALTER TABLE user_identities DROP CONSTRAINT IF EXISTS user_identities_kind_check;
ALTER TABLE user_identities
    ADD CONSTRAINT user_identities_kind_check CHECK (kind = 'email');

ALTER TABLE verification_challenges DROP CONSTRAINT IF EXISTS verification_challenges_kind_check;
ALTER TABLE verification_challenges
    ADD CONSTRAINT verification_challenges_kind_check CHECK (kind = 'email');

ALTER TABLE verification_challenges DROP CONSTRAINT IF EXISTS verification_challenges_purpose_check;
ALTER TABLE verification_challenges
    ADD CONSTRAINT verification_challenges_purpose_check CHECK (purpose IN ('register', 'reset'));

-- +goose Down
-- Removing an authentication method is intentionally irreversible. Rolling
-- this migration down must not make the database accept unsupported identities.
SELECT 1;
