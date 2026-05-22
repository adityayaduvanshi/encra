CREATE TABLE IF NOT EXISTS public_keys (
  user_id    TEXT        PRIMARY KEY,
  public_key TEXT        NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS message_queue (
  id           BIGSERIAL   PRIMARY KEY,
  recipient_id TEXT        NOT NULL,
  sender_id    TEXT        NOT NULL,
  ciphertext   TEXT        NOT NULL,
  nonce        TEXT        NOT NULL,
  created_at   TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_message_queue_recipient
  ON message_queue (recipient_id, created_at);
