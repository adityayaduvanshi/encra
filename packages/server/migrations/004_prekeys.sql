-- Migration 004: X3DH prekey infrastructure
-- Adds the key material needed for asynchronous, authenticated session setup:
--   * identity_keys     — one long-term Ed25519 identity key per device
--   * signed_prekeys    — the current signed prekey per device (latest wins)
--   * one_time_prekeys  — a per-device pool, each consumed (deleted) on fetch
--
-- These tables are additive. The existing public_keys table is retained for
-- device discovery (GET /v1/keys/:userId returns the device list).

-- Identity keys: one Ed25519 identity public key per device.
CREATE TABLE IF NOT EXISTS identity_keys (
  user_id      TEXT        NOT NULL,
  device_id    TEXT        NOT NULL,
  identity_key TEXT        NOT NULL,            -- Ed25519 public key (base64)
  created_at   TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, device_id)
);

-- Signed prekeys: the current signed prekey per device. Rotated periodically;
-- we keep only the latest (upsert on the device key).
CREATE TABLE IF NOT EXISTS signed_prekeys (
  user_id    TEXT        NOT NULL,
  device_id  TEXT        NOT NULL,
  key_id     INTEGER     NOT NULL,
  public_key TEXT        NOT NULL,              -- X25519 public key (base64)
  signature  TEXT        NOT NULL,              -- Ed25519 signature (base64)
  created_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (user_id, device_id)
);

-- One-time prekeys: a pool per device. Each row is handed out at most once and
-- deleted on consumption, giving the first message forward secrecy.
CREATE TABLE IF NOT EXISTS one_time_prekeys (
  id         BIGSERIAL   PRIMARY KEY,
  user_id    TEXT        NOT NULL,
  device_id  TEXT        NOT NULL,
  key_id     INTEGER     NOT NULL,
  public_key TEXT        NOT NULL,              -- X25519 public key (base64)
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE (user_id, device_id, key_id)
);

-- Efficient FIFO consumption of the oldest unused prekey per device.
CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_device
  ON one_time_prekeys (user_id, device_id, id);
