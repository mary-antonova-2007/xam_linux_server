CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    auth_public_key TEXT NOT NULL UNIQUE,
    exchange_public_key TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_challenges (
    challenge_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires_at ON auth_challenges (expires_at);

CREATE TABLE IF NOT EXISTS attachments (
    attachment_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    object_key TEXT NOT NULL UNIQUE,
    ciphertext_size BIGINT NOT NULL,
    mime_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_attachments_expires_at ON attachments (expires_at);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    sender_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    ciphertext TEXT NOT NULL,
    nonce TEXT NOT NULL,
    message_type TEXT NOT NULL,
    attachment_id TEXT REFERENCES attachments(attachment_id) ON DELETE SET NULL,
    idempotency_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_idempotency ON messages (sender_device_id, idempotency_key);
CREATE INDEX IF NOT EXISTS idx_messages_recipient_created_at ON messages (recipient_device_id, created_at);
CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages (expires_at);
