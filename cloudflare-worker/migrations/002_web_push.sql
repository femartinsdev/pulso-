-- PULSO 2.0 · Migration Aditiva 002 — Web Push (Cloudflare D1)
-- Preserva 100% das tabelas existentes (device_tokens, intake_events, delivery_logs).
-- Aplique com:
--   npx wrangler d1 execute pulso-c6-intake-db --remote --file=./migrations/002_web_push.sql

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS push_preferences (
  owner_key TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  tone TEXT NOT NULL DEFAULT 'sarcastic',
  privacy_mode INTEGER NOT NULL DEFAULT 0,
  notify_income INTEGER NOT NULL DEFAULT 1,
  notify_expense INTEGER NOT NULL DEFAULT 1,
  notify_categorization INTEGER NOT NULL DEFAULT 1,
  last_phrase_index INTEGER NOT NULL DEFAULT -1,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS push_deliveries (
  id TEXT PRIMARY KEY,
  intake_event_id TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  sent_at TEXT NOT NULL,
  UNIQUE(intake_event_id, subscription_id)
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_active
  ON push_subscriptions (revoked_at, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_push_deliveries_sent_at
  ON push_deliveries (sent_at DESC);
