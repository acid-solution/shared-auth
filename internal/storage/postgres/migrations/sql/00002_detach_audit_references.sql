-- +goose Up
-- Audit events must survive account/session deletion and must also be able to
-- record invalid session selectors that never existed.
ALTER TABLE auth_events DROP CONSTRAINT IF EXISTS auth_events_user_id_fkey;
ALTER TABLE auth_events DROP CONSTRAINT IF EXISTS auth_events_session_id_fkey;

-- +goose Down
ALTER TABLE auth_events
    ADD CONSTRAINT auth_events_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE auth_events
    ADD CONSTRAINT auth_events_session_id_fkey
    FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE SET NULL;
