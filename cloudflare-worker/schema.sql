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
