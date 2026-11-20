-- PULSO · Cloudflare D1 Schema (Camada Gratuita)
-- Armazena apenas hashes SHA-256 dos tokens do iPhone, fila idempotente do C6 Bank
-- e logs de diagnóstico sem credenciais nem códigos OTP.

CREATE TABLE IF NOT EXISTS device_tokens (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS intake_events (
  id TEXT PRIMARY KEY,
  idempotency_key TEXT NOT NULL UNIQUE,
  token_id TEXT NOT NULL,
  bank_origin TEXT NOT NULL,
  raw_summary TEXT NOT NULL,
  merchant_name TEXT,
  proposed_description TEXT NOT NULL,
  proposed_amount_cents INTEGER NOT NULL,
  proposed_type TEXT NOT NULL,
  confidence TEXT NOT NULL,
  ambiguity_reason TEXT,
  occurred_at TEXT NOT NULL,
  received_at TEXT NOT NULL,
  acked_at TEXT,
  ack_target_collection TEXT,
  ack_doc_id TEXT
);

CREATE TABLE IF NOT EXISTS delivery_logs (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  route TEXT NOT NULL,
  outcome TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  summary TEXT,
  token_id TEXT,
  http_status INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_intake_events_acked_received
  ON intake_events (acked_at, received_at);

CREATE INDEX IF NOT EXISTS idx_delivery_logs_created_at
  ON delivery_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_device_tokens_active
  ON device_tokens (revoked_at, created_at DESC);

-- PULSO 2.0 · Web Push (inscrições, preferências de tom/privacidade e controle anti-duplicidade)

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

