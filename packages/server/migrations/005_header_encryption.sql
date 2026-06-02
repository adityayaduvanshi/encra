-- Migration 005: header encryption + X3DH prekey message on the wire
--
-- The Double Ratchet now encrypts its header, so the offline queue stores the
-- opaque encrypted header (base64) instead of the plaintext JSON header. The
-- X3DH prekey message can no longer ride inside the (encrypted) header, so it
-- travels as its own column for session-initiating messages.
--
-- The legacy `header` column is retained (nullable) so the migration is
-- non-destructive; new rows use `enc_header` and `prekey`.

ALTER TABLE message_queue
  ADD COLUMN IF NOT EXISTS enc_header TEXT,
  ADD COLUMN IF NOT EXISTS prekey     JSONB;

-- The old plaintext header column is no longer written; relax its NOT NULL so
-- inserts that omit it succeed.
ALTER TABLE message_queue ALTER COLUMN header DROP NOT NULL;
