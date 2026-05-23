-- Add the ratchet header and sender display name to the offline message queue.
--
-- The header is required by the Double Ratchet receiver to derive the per-message
-- key.  Without it, flushQueuedMessages delivers a message that the client's
-- !msg.header guard immediately discards — making every offline message silently lost.
--
-- sender_name is the display name set by the sender client (plaintext, best-effort).

ALTER TABLE message_queue
  ADD COLUMN IF NOT EXISTS header      JSONB NOT NULL DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS sender_name TEXT;
