-- Migration 003: Multi-device support
-- Adds device_id to public_keys so each device gets its own key entry.
-- Adds recipient_device_id to message_queue for device-specific offline delivery.

-- Step 1: Add device_id to public_keys (existing rows get 'default')
ALTER TABLE public_keys ADD COLUMN IF NOT EXISTS device_id TEXT NOT NULL DEFAULT 'default';

-- Step 2: Replace single-column PK with composite (user_id, device_id)
ALTER TABLE public_keys DROP CONSTRAINT IF EXISTS public_keys_pkey;
ALTER TABLE public_keys ADD PRIMARY KEY (user_id, device_id);

-- Step 3: Add device_id column to message_queue for device-specific routing
ALTER TABLE message_queue ADD COLUMN IF NOT EXISTS recipient_device_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE message_queue ADD COLUMN IF NOT EXISTS sender_device_id    TEXT NOT NULL DEFAULT 'default';

-- Step 4: Rebuild index to include device_id for efficient per-device queue lookup
DROP INDEX IF EXISTS idx_message_queue_recipient;
CREATE INDEX IF NOT EXISTS idx_message_queue_recipient
  ON message_queue (recipient_id, recipient_device_id, created_at);
