import assert from 'node:assert/strict';
import test from 'node:test';
import {
  handleWorkerRequest,
  type D1DatabaseLike,
  type D1PreparedStatementLike,
  type WorkerEnv,
} from '../src/index.ts';
import { clearJwksCacheForTests } from '../src/security.ts';
import {
  buildPushCopyForEvent,
  toBase64Url as toWebPushBase64Url,
} from '../src/webPush.ts';

/**
 * Mock fiel em memória do Cloudflare D1 apenas para testes automatizados locais.
 */
class InMemoryD1 implements D1DatabaseLike {
  deviceTokens: Array<Record<string, unknown>> = [];
  intakeEvents: Array<Record<string, unknown>> = [];
  deliveryLogs: Array<Record<string, unknown>> = [];
  pushSubscriptions: Array<Record<string, unknown>> = [];
  pushPreferences: Array<Record<string, unknown>> = [];
  pushDeliveries: Array<Record<string, unknown>> = [];

  prepare(query: string): D1PreparedStatementLike {
    const db = this;
    const normalized = query.replace(/\s+/g, ' ').trim();
    let bound: unknown[] = [];

    const stmt: D1PreparedStatementLike = {
      bind(...values: unknown[]) {
        bound = values;
        return stmt;
      },
      async first<T = Record<string, unknown>>(): Promise<T | null> {
        if (normalized.includes('SELECT COUNT(*) AS cnt FROM intake_events WHERE acked_at IS NULL')) {
          return {
            cnt: db.intakeEvents.filter((e) => e.acked_at === null).length,
          } as T;
        }
        if (normalized.includes('SELECT COUNT(*) AS cnt FROM intake_events WHERE acked_at IS NOT NULL')) {
          return {
            cnt: db.intakeEvents.filter((e) => e.acked_at !== null).length,
          } as T;
        }
        if (normalized.includes('SELECT COUNT(*) AS cnt FROM device_tokens WHERE revoked_at IS NULL')) {
          return {
            cnt: db.deviceTokens.filter((t) => t.revoked_at === null).length,
          } as T;
        }
        if (normalized.includes('SELECT COUNT(*) AS cnt FROM push_subscriptions WHERE revoked_at IS NULL')) {
          return {
            cnt: db.pushSubscriptions.filter((s) => s.revoked_at === null).length,
          } as T;
        }
        if (normalized.includes('FROM push_preferences WHERE owner_key = ?')) {
          const [ownerKey] = bound;
          return (db.pushPreferences.find((p) => p.owner_key === ownerKey) ?? null) as T | null;
        }
        if (normalized.includes('SELECT id FROM push_subscriptions WHERE endpoint = ?')) {
          const [endpoint] = bound;
          const row = db.pushSubscriptions.find((s) => s.endpoint === endpoint);
          return (row ? { id: row.id } : null) as T | null;
        }
        return null;
      },
      async all<T = Record<string, unknown>>(): Promise<{ results: T[] }> {
        if (normalized.includes('FROM device_tokens WHERE revoked_at IS NULL')) {
          return {
            results: db.deviceTokens.filter((t) => t.revoked_at === null) as T[],
          };
        }
        if (normalized.includes('FROM device_tokens ORDER BY created_at DESC')) {
          return {
            results: [...db.deviceTokens].sort((a, b) =>
              String(b.created_at).localeCompare(String(a.created_at))
            ) as T[],
          };
        }
        if (normalized.includes('FROM intake_events WHERE acked_at IS NULL')) {
          return {
            results: db.intakeEvents
              .filter((e) => e.acked_at === null)
              .sort((a, b) => String(a.occurred_at).localeCompare(String(b.occurred_at))) as T[],
          };
        }
        if (normalized.includes('FROM delivery_logs ORDER BY created_at DESC')) {
          return {
            results: [...db.deliveryLogs]
              .sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)))
              .slice(0, 50) as T[],
          };
        }
        if (normalized.includes('FROM push_subscriptions WHERE revoked_at IS NULL')) {
          return {
            results: db.pushSubscriptions
              .filter((s) => s.revoked_at === null)
              .sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at))) as T[],
          };
        }
        return { results: [] };
      },
      async run(): Promise<{ success: boolean; meta?: { changes?: number } }> {
        if (normalized.startsWith('INSERT INTO device_tokens')) {
          const [id, label, token_prefix, token_hash, created_at] = bound;
          db.deviceTokens.push({
            id,
            label,
            token_prefix,
            token_hash,
            created_at,
            last_used_at: null,
            revoked_at: null,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('UPDATE device_tokens SET last_used_at')) {
          const [last_used_at, id] = bound;
          const row = db.deviceTokens.find((t) => t.id === id);
          if (row) {
            row.last_used_at = last_used_at;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('UPDATE device_tokens SET revoked_at')) {
          const [revoked_at, id] = bound;
          const row = db.deviceTokens.find((t) => t.id === id && t.revoked_at === null);
          if (row) {
            row.revoked_at = revoked_at;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('INSERT OR IGNORE INTO intake_events')) {
          const [
            id,
            idempotency_key,
            token_id,
            bank_origin,
            raw_summary,
            merchant_name,
            proposed_description,
            proposed_amount_cents,
            proposed_type,
            confidence,
            ambiguity_reason,
            occurred_at,
            received_at,
          ] = bound;

          const exists = db.intakeEvents.some((e) => e.idempotency_key === idempotency_key);
          if (exists) {
            return { success: true, meta: { changes: 0 } };
          }
          db.intakeEvents.push({
            id,
            idempotency_key,
            token_id,
            bank_origin,
            raw_summary,
            merchant_name,
            proposed_description,
            proposed_amount_cents,
            proposed_type,
            confidence,
            ambiguity_reason,
            occurred_at,
            received_at,
            acked_at: null,
            ack_target_collection: null,
            ack_doc_id: null,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('UPDATE intake_events SET acked_at')) {
          const [acked_at, ack_target_collection, ack_doc_id, id] = bound;
          const row = db.intakeEvents.find((e) => e.id === id && e.acked_at === null);
          if (row) {
            row.acked_at = acked_at;
            row.ack_target_collection = ack_target_collection;
            row.ack_doc_id = ack_doc_id;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('INSERT INTO delivery_logs')) {
          const [id, created_at, route, outcome, reason_code, summary, token_id, http_status] = bound;
          db.deliveryLogs.push({
            id,
            created_at,
            route,
            outcome,
            reason_code,
            summary,
            token_id,
            http_status,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('DELETE FROM delivery_logs')) {
          const limit = Number(bound[0] ?? 200);
          db.deliveryLogs.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
          db.deliveryLogs = db.deliveryLogs.slice(0, limit);
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('DELETE FROM intake_events')) {
          const cutoff = String(bound[0]);
          const before = db.intakeEvents.length;
          db.intakeEvents = db.intakeEvents.filter(
            (e) => e.acked_at === null || String(e.acked_at) >= cutoff
          );
          return { success: true, meta: { changes: before - db.intakeEvents.length } };
        }
        if (normalized.startsWith('INSERT INTO push_subscriptions')) {
          const [id, endpoint, p256dh, auth, user_agent, created_at, updated_at] = bound;
          db.pushSubscriptions.push({
            id,
            endpoint,
            p256dh,
            auth,
            user_agent,
            created_at,
            updated_at,
            revoked_at: null,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('UPDATE push_subscriptions SET p256dh')) {
          const [p256dh, auth, user_agent, updated_at, id] = bound;
          const row = db.pushSubscriptions.find((s) => s.id === id);
          if (row) {
            row.p256dh = p256dh;
            row.auth = auth;
            row.user_agent = user_agent;
            row.updated_at = updated_at;
            row.revoked_at = null;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('UPDATE push_subscriptions SET revoked_at = ?, updated_at = ? WHERE endpoint = ?')) {
          const [revoked_at, updated_at, endpoint] = bound;
          let changes = 0;
          for (const row of db.pushSubscriptions) {
            if (row.endpoint === endpoint && row.revoked_at === null) {
              row.revoked_at = revoked_at;
              row.updated_at = updated_at;
              changes += 1;
            }
          }
          return { success: true, meta: { changes } };
        }
        if (normalized.startsWith('UPDATE push_subscriptions SET revoked_at = ?, updated_at = ? WHERE id = ?')) {
          const [revoked_at, updated_at, id] = bound;
          const row = db.pushSubscriptions.find((s) => s.id === id);
          if (row) {
            row.revoked_at = revoked_at;
            row.updated_at = updated_at;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        if (normalized.startsWith('UPDATE push_subscriptions SET revoked_at = ?, updated_at = ? WHERE revoked_at IS NULL')) {
          const [revoked_at, updated_at] = bound;
          let changes = 0;
          for (const row of db.pushSubscriptions) {
            if (row.revoked_at === null) {
              row.revoked_at = revoked_at;
              row.updated_at = updated_at;
              changes += 1;
            }
          }
          return { success: true, meta: { changes } };
        }
        if (normalized.startsWith('INSERT INTO push_preferences')) {
          const [
            owner_key,
            enabled,
            tone,
            privacy_mode,
            notify_income,
            notify_expense,
            notify_categorization,
            last_phrase_index,
            updated_at,
          ] = bound;
          const existing = db.pushPreferences.find((p) => p.owner_key === owner_key);
          if (existing) {
            existing.enabled = enabled;
            existing.tone = tone;
            existing.privacy_mode = privacy_mode;
            existing.notify_income = notify_income;
            existing.notify_expense = notify_expense;
            existing.notify_categorization = notify_categorization;
            existing.last_phrase_index = last_phrase_index;
            existing.updated_at = updated_at;
          } else {
            db.pushPreferences.push({
              owner_key,
              enabled,
              tone,
              privacy_mode,
              notify_income,
              notify_expense,
              notify_categorization,
              last_phrase_index,
              updated_at,
            });
          }
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('INSERT OR IGNORE INTO push_deliveries')) {
          const [id, intake_event_id, subscription_id, status, http_status, sent_at] = bound;
          const exists = db.pushDeliveries.some(
            (d) => d.intake_event_id === intake_event_id && d.subscription_id === subscription_id
          );
          if (exists) {
            return { success: true, meta: { changes: 0 } };
          }
          db.pushDeliveries.push({
            id,
            intake_event_id,
            subscription_id,
            status,
            http_status,
            sent_at,
          });
          return { success: true, meta: { changes: 1 } };
        }
        if (normalized.startsWith('UPDATE push_deliveries SET status = ?')) {
          const [status, http_status, id] = bound;
          const row = db.pushDeliveries.find((d) => d.id === id);
          if (row) {
            row.status = status;
            row.http_status = http_status;
            return { success: true, meta: { changes: 1 } };
          }
          return { success: true, meta: { changes: 0 } };
        }
        return { success: true, meta: { changes: 0 } };
      },
    };

    return stmt;
  }
}

function toBase64Url(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

async function createTestSigner() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );

  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  const kid = 'test-key-1';

  const signJwt = async (claims: Record<string, unknown>) => {
    const header = toBase64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid }));
    const payload = toBase64Url(JSON.stringify(claims));
    const data = new TextEncoder().encode(`${header}.${payload}`);
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', keyPair.privateKey, data);
    return `${header}.${payload}.${toBase64Url(new Uint8Array(sig))}`;
  };

  return {
    jwksOverride: { [kid]: publicJwk },
    signJwt,
  };
}

const ORIGIN = 'https://ais-dev-rzytziincbb4xitfxirpmx-898906846392.us-east1.run.app';
const PROJECT_ID = 'knitted-backup-rnj8s';
const OWNER_EMAIL = 'owner@example.com';
const NOW_MS = Date.parse('2026-11-19T14:00:00.000Z');

function makeBaseClaims(overrides: Record<string, unknown> = {}) {
  const nowSec = Math.floor(NOW_MS / 1000);
  return {
    aud: PROJECT_ID,
    iss: `https://securetoken.google.com/${PROJECT_ID}`,
    sub: 'uid-owner-123',
    iat: nowSec - 60,
    auth_time: nowSec - 60,
    exp: nowSec + 3600,
    email: OWNER_EMAIL,
    email_verified: true,
    ...overrides,
  };
}

function createEnv(db: InMemoryD1): WorkerEnv {
  return {
    DB: db,
    FIREBASE_PROJECT_ID: PROJECT_ID,
    AUTHORIZED_OWNER_EMAIL: OWNER_EMAIL,
    ALLOWED_ORIGINS: ORIGIN,
  };
}

test('Worker rejeita rotas administrativas sem Firebase JWT válido ou de outro usuário/origem', async () => {
  clearJwksCacheForTests();
  const db = new InMemoryD1();
  const env = createEnv(db);
  const { jwksOverride, signJwt } = await createTestSigner();

  // Sem Authorization
  const noAuthRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', { headers: { Origin: ORIGIN } }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(noAuthRes.status, 401);

  // Origem não autorizada
  const validJwt = await signJwt(makeBaseClaims());
  const badOriginRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: 'https://evil.example', Authorization: `Bearer ${validJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(badOriginRes.status, 403);

  // Outro e-mail autenticado no Google
  const intruderJwt = await signJwt(makeBaseClaims({ email: 'outro@gmail.com' }));
  const intruderRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${intruderJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(intruderRes.status, 401);

  // E-mail não verificado
  const unverifiedJwt = await signJwt(makeBaseClaims({ email_verified: false }));
  const unverifiedRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${unverifiedJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(unverifiedRes.status, 401);

  // Token expirado
  const expiredJwt = await signJwt(makeBaseClaims({ exp: Math.floor(NOW_MS / 1000) - 10 }));
  const expiredRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${expiredJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(expiredRes.status, 401);

  // Assinatura adulterada
  const tamperedJwt = `${validJwt.slice(0, -4)}AAAA`;
  const tamperedRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${tamperedJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(tamperedRes.status, 401);

  // Token legítimo da titular
  const okRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/health', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${validJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(okRes.status, 200);
  const body = (await okRes.json()) as { ok: boolean; ownerEmail: string };
  assert.equal(body.ok, true);
  assert.equal(body.ownerEmail, OWNER_EMAIL);
});

test('Worker bloqueia credenciais na URL, emite token revogável (hash SHA-256 no D1) e revoga imediatamente', async () => {
  const db = new InMemoryD1();
  const env = createEnv(db);
  const { jwksOverride, signJwt } = await createTestSigner();
  const ownerJwt = await signJwt(makeBaseClaims());

  // 1. Cria token do iPhone autenticado como titular
  const createRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/tokens', {
      method: 'POST',
      headers: {
        Origin: ORIGIN,
        Authorization: `Bearer ${ownerJwt}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ label: 'iPhone Principal' }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(createRes.status, 201);
  const created = (await createRes.json()) as {
    token: { id: string; tokenPrefix: string };
    plaintextToken: string;
  };
  assert.ok(created.plaintextToken.startsWith('pls_c6_'));
  assert.ok(created.plaintextToken.length >= 45);

  // Confirma que D1 NÃO guarda plaintext, apenas hash SHA-256 de 64 caracteres hex
  assert.equal(db.deviceTokens.length, 1);
  assert.notEqual(db.deviceTokens[0].token_hash, created.plaintextToken);
  assert.match(String(db.deviceTokens[0].token_hash), /^[0-9a-f]{64}$/);

  // 2. Tentativa de enviar token na query string é bloqueada com HTTP 400
  const urlTokenRes = await handleWorkerRequest(
    new Request(`https://worker.test/api/v1/intake?token=${created.plaintextToken}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'C6 Bank: Compra aprovada no débito de R$ 10,00 em PADARIA' }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(urlTokenRes.status, 400);
  // Confirma que o plaintext não vazou no delivery_logs
  assert.equal(
    db.deliveryLogs.some((l) => String(l.summary ?? '').includes(created.plaintextToken)),
    false
  );

  // 3. Envio legítimo via Header Authorization: Bearer funciona
  const okIntake = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/intake', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${created.plaintextToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        bank: 'C6 Bank',
        text: 'C6 Bank: Compra aprovada no débito de R$ 28,90 em PADARIA CENTRAL',
        receivedAt: '2026-11-19T14:00:00.000Z',
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(okIntake.status, 201);

  // 4. Revogação imediata do token
  const revokeRes = await handleWorkerRequest(
    new Request(`https://worker.test/api/v1/tokens/${created.token.id}`, {
      method: 'DELETE',
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(revokeRes.status, 200);

  // 5. Mesmo token revogado agora retorna 401
  const blockedRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/intake', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${created.plaintextToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        bank: 'C6 Bank',
        text: 'C6 Bank: Pix enviado de R$ 15,00 para JOAO',
        receivedAt: '2026-11-19T14:05:00.000Z',
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(blockedRes.status, 401);
});

test('Worker filtra OTP/promoções/outros bancos, distingue crédito/própria, preserva 2 compras legítimas do mesmo valor e faz sync+ack', async () => {
  const db = new InMemoryD1();
  const env = createEnv(db);
  const { jwksOverride, signJwt } = await createTestSigner();
  const ownerJwt = await signJwt(makeBaseClaims());

  const tokRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/tokens', {
      method: 'POST',
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
      body: JSON.stringify({ label: 'iPhone Teste' }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  const { plaintextToken } = (await tokRes.json()) as { plaintextToken: string };

  const postIntake = (payload: Record<string, unknown>) =>
    handleWorkerRequest(
      new Request('https://worker.test/api/v1/intake', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${plaintextToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      }),
      env,
      { nowMs: NOW_MS, jwksOverride }
    );

  // OTP bloqueado e código 849201 NUNCA salvo em nenhum lugar do D1
  const otpRes = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Seu código de verificação é 849201. Não compartilhe este código.',
    receivedAt: '2026-11-19T14:00:00.000Z',
  });
  assert.equal(otpRes.status, 200);
  const otpJson = (await otpRes.json()) as { status: string; reasonCode: string };
  assert.equal(otpJson.status, 'ignored');
  assert.equal(otpJson.reasonCode, 'ignored_otp');
  assert.equal(JSON.stringify(db.deliveryLogs).includes('849201'), false);
  assert.equal(db.intakeEvents.length, 0);

  // Promoção bloqueada
  const promoRes = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Aproveite cashback de R$ 50,00 com pontos Átomos hoje!',
    receivedAt: '2026-11-19T14:01:00.000Z',
  });
  assert.equal(((await promoRes.json()) as { reasonCode: string }).reasonCode, 'ignored_promo');

  // Outro banco bloqueado (endpoint automático aceita apenas C6 Bank)
  const caixaRes = await postIntake({
    bank: 'Caixa Tem',
    text: 'Caixa Tem: Você recebeu um Pix de R$ 100,00 de MARIA',
    receivedAt: '2026-11-19T14:02:00.000Z',
  });
  assert.equal(((await caixaRes.json()) as { reasonCode: string }).reasonCode, 'ignored_bank');

  // Compra 1 no débito R$ 15,00 às 09:10 (alta confiança)
  const buy1 = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Compra aprovada no débito de R$ 15,00 em CAFE DA ESQUINA',
    receivedAt: '2026-11-19T09:10:00-03:00',
  });
  assert.equal(buy1.status, 201);
  const buy1Json = (await buy1.json()) as { confidence: string; proposedType: string };
  assert.equal(buy1Json.confidence, 'high');
  assert.equal(buy1Json.proposedType, 'expense');

  // Reenvio idêntico da Compra 1 -> bloqueado por idempotência (duplicate)
  const buy1Retry = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Compra aprovada no débito de R$ 15,00 em CAFE DA ESQUINA',
    receivedAt: '2026-11-19T09:10:00-03:00',
  });
  assert.equal(buy1Retry.status, 200);
  assert.equal(((await buy1Retry.json()) as { status: string }).status, 'duplicate');

  // Compra 2 legítima do MESMO valor R$ 15,00 no MESMO dia às 15:40 -> ACEITA!
  const buy2 = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Compra aprovada no débito de R$ 15,00 em CAFE DA ESQUINA',
    receivedAt: '2026-11-19T15:40:00-03:00',
  });
  assert.equal(buy2.status, 201);

  // Compra no cartão de crédito -> marcada como ambiguous (credit_card_purchase)
  const creditRes = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Compra aprovada no crédito de R$ 120,00 em LOJA TESTE',
    receivedAt: '2026-11-19T16:00:00-03:00',
  });
  assert.equal(creditRes.status, 201);
  const creditJson = (await creditRes.json()) as { confidence: string; ambiguityReason: string };
  assert.equal(creditJson.confidence, 'ambiguous');
  assert.equal(creditJson.ambiguityReason, 'credit_card_purchase');

  // Pix de mesma titularidade / Caixa Tem -> ambiguous (possible_own_transfer)
  const ownTransferRes = await postIntake({
    bank: 'C6 Bank',
    text: 'C6 Bank: Pix recebido de R$ 300,00 de Caixa Tem mesma titularidade',
    receivedAt: '2026-11-19T16:15:00-03:00',
  });
  assert.equal(ownTransferRes.status, 201);
  const ownTransferJson = (await ownTransferRes.json()) as {
    confidence: string;
    proposedType: string;
    ambiguityReason: string;
  };
  assert.equal(ownTransferJson.confidence, 'ambiguous');
  assert.equal(ownTransferJson.proposedType, 'transfer');
  assert.equal(ownTransferJson.ambiguityReason, 'possible_own_transfer');

  // PULSO lê /api/v1/pending -> 4 eventos (buy1, buy2, credit, ownTransfer)
  const pendingRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/pending', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(pendingRes.status, 200);
  const pendingBody = (await pendingRes.json()) as { events: Array<{ id: string }> };
  assert.equal(pendingBody.events.length, 4);

  // PULSO confirma ACK após persistir no Firestore
  const ackRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/ack', {
      method: 'POST',
      headers: {
        Origin: ORIGIN,
        Authorization: `Bearer ${ownerJwt}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        items: pendingBody.events.map((e) => ({
          id: e.id,
          targetCollection: 'transactions',
          docId: `tx-${e.id}`,
        })),
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(ackRes.status, 200);
  assert.equal(((await ackRes.json()) as { ackedCount: number }).ackedCount, 4);

  // Fila agora está vazia
  const pendingAfter = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/pending', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(((await pendingAfter.json()) as { events: unknown[] }).events.length, 0);
});

async function generateTestVapidKeys(): Promise<{ publicKey: string; privateKey: string }> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const jwkPriv = await crypto.subtle.exportKey('jwk', pair.privateKey);
  assert.ok(jwkPriv.d);
  return {
    publicKey: toWebPushBase64Url(rawPub),
    privateKey: jwkPriv.d,
  };
}

async function generateTestSubscriptionKeys(): Promise<{ p256dh: string; auth: string }> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const auth = new Uint8Array(16);
  crypto.getRandomValues(auth);
  return {
    p256dh: toWebPushBase64Url(rawPub),
    auth: toWebPushBase64Url(auth),
  };
}

test('PULSO 2.0 Web Push: envia exatamente 1 push RFC 8291 por evento C6 aceito, ignora OTP/duplicado, respeita privacidade e revoga 410', async () => {
  clearJwksCacheForTests();
  const db = new InMemoryD1();
  const vapid = await generateTestVapidKeys();
  const env: WorkerEnv = {
    ...createEnv(db),
    VAPID_PUBLIC_KEY: vapid.publicKey,
    VAPID_PRIVATE_KEY: vapid.privateKey,
    VAPID_SUBJECT: `mailto:${OWNER_EMAIL}`,
  };
  const { jwksOverride, signJwt } = await createTestSigner();
  const ownerJwt = await signJwt(makeBaseClaims());

  // 1. Sem JWT da titular -> 401
  const unauthPushRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/config', { headers: { Origin: ORIGIN } }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(unauthPushRes.status, 401);

  // 2. GET /api/v1/push/config retorna pushConfigured=true e tom padrão 'sarcastic'
  const cfgRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/config', {
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(cfgRes.status, 200);
  const cfg = (await cfgRes.json()) as {
    ok: boolean;
    pushConfigured: boolean;
    vapidPublicKey: string;
    preferences: { tone: string; privacyMode: boolean };
  };
  assert.equal(cfg.ok, true);
  assert.equal(cfg.pushConfigured, true);
  assert.equal(cfg.vapidPublicKey, vapid.publicKey);
  assert.equal(cfg.preferences.tone, 'sarcastic');
  assert.equal(cfg.preferences.privacyMode, false);

  // 3. Inscreve iPhone em POST /api/v1/push/subscribe
  const subKeys = await generateTestSubscriptionKeys();
  const endpoint = 'https://web.push.apple.com/QTestSubscriptionEndpoint01';
  const subRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/subscribe', {
      method: 'POST',
      headers: {
        Origin: ORIGIN,
        Authorization: `Bearer ${ownerJwt}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        endpoint,
        keys: subKeys,
        userAgent: 'iPhone PWA Safari',
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(subRes.status, 201);
  assert.equal(db.pushSubscriptions.length, 1);

  // 4. Cria token do iPhone para /api/v1/intake
  const tokRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/tokens', {
      method: 'POST',
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
      body: JSON.stringify({ label: 'iPhone Push Test' }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  const { plaintextToken } = (await tokRes.json()) as { plaintextToken: string };

  // Captura chamadas HTTP ao Apple Push Service
  const sentPushRequests: Array<{ url: string; headers: Headers; bodyLength: number }> = [];
  let nextPushStatus = 201;
  const mockFetch: typeof fetch = async (input, init) => {
    const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    const headers = new Headers(init?.headers);
    const bodyBuf = init?.body instanceof ArrayBuffer ? init.body.byteLength : 0;
    sentPushRequests.push({ url: urlStr, headers, bodyLength: bodyBuf });
    return new Response(null, { status: nextPushStatus });
  };

  // 5. OTP NÃO dispara push
  const otpRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/intake', {
      method: 'POST',
      headers: { Authorization: `Bearer ${plaintextToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        bank: 'C6 Bank',
        text: 'C6 Bank: Seu código OTP é 991822.',
        receivedAt: '2026-11-19T14:00:00-03:00',
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride, fetchImpl: mockFetch }
  );
  assert.equal(otpRes.status, 200);
  assert.equal(sentPushRequests.length, 0);

  // 6. Transação C6 aceita dispara EXATAMENTE 1 push criptografado RFC 8291 + VAPID
  const buyPayload = {
    bank: 'C6 Bank',
    text: 'C6 Bank: Compra aprovada no débito de R$ 42,50 em PIZZARIA DO BAIRRO',
    receivedAt: '2026-11-19T14:10:00-03:00',
  };
  const tx1Res = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/intake', {
      method: 'POST',
      headers: { Authorization: `Bearer ${plaintextToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(buyPayload),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride, fetchImpl: mockFetch }
  );
  assert.equal(tx1Res.status, 201);
  assert.equal(sentPushRequests.length, 1);
  assert.equal(sentPushRequests[0].url, endpoint);
  assert.equal(sentPushRequests[0].headers.get('Content-Encoding'), 'aes128gcm');
  assert.match(sentPushRequests[0].headers.get('Authorization') ?? '', /^vapid t=.+, k=.+$/);
  assert.ok(sentPushRequests[0].bodyLength > 86); // header aes128gcm (86B) + ciphertext + tag
  assert.equal(db.pushDeliveries.length, 1);
  assert.equal(db.pushDeliveries[0].status, 'sent');

  // 7. Reenvio duplicado NÃO envia segundo push
  const tx1Dup = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/intake', {
      method: 'POST',
      headers: { Authorization: `Bearer ${plaintextToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(buyPayload),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride, fetchImpl: mockFetch }
  );
  assert.equal(tx1Dup.status, 200);
  assert.equal(sentPushRequests.length, 1);

  // 8. Teste de copy: modo privacidade oculta valor e estabelecimento, e rotação anti-repetição funciona
  const firstCopy = buildPushCopyForEvent({
    eventId: 'evt_1',
    proposedType: 'expense',
    proposedAmountCents: 4250,
    proposedDescription: 'PIZZARIA DO BAIRRO',
    merchantName: 'PIZZARIA DO BAIRRO',
    tone: 'sarcastic',
    privacyMode: false,
    lastPhraseIndex: -1,
  });
  const secondCopy = buildPushCopyForEvent({
    eventId: 'evt_2',
    proposedType: 'expense',
    proposedAmountCents: 4250,
    proposedDescription: 'PIZZARIA DO BAIRRO',
    merchantName: 'PIZZARIA DO BAIRRO',
    tone: 'sarcastic',
    privacyMode: false,
    lastPhraseIndex: firstCopy.nextPhraseIndex,
  });
  assert.notEqual(firstCopy.payload.body, secondCopy.payload.body);
  assert.ok(firstCopy.payload.body.includes('R$ 42,50'));

  const privateCopy = buildPushCopyForEvent({
    eventId: 'evt_3',
    proposedType: 'expense',
    proposedAmountCents: 99990,
    proposedDescription: 'JOALHERIA SECRETA',
    merchantName: 'JOALHERIA SECRETA',
    tone: 'sarcastic',
    privacyMode: true,
    lastPhraseIndex: 0,
  });
  assert.equal(privateCopy.payload.body.includes('999'), false);
  assert.equal(privateCopy.payload.body.includes('JOALHERIA'), false);

  // 9. PUT /api/v1/push/preferences alterna para modo privacidade + tom discreto
  const prefRes = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/preferences', {
      method: 'PUT',
      headers: {
        Origin: ORIGIN,
        Authorization: `Bearer ${ownerJwt}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        enabled: true,
        tone: 'discreet',
        privacyMode: true,
        notifyIncome: true,
        notifyExpense: true,
        notifyCategorization: true,
      }),
    }),
    env,
    { nowMs: NOW_MS, jwksOverride }
  );
  assert.equal(prefRes.status, 200);
  const prefJson = (await prefRes.json()) as { preferences: { tone: string; privacyMode: boolean } };
  assert.equal(prefJson.preferences.tone, 'discreet');
  assert.equal(prefJson.preferences.privacyMode, true);

  // 10. POST /api/v1/push/test entrega com sucesso e 410 Gone revoga inscrição expirada
  const testPushOk = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/test', {
      method: 'POST',
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride, fetchImpl: mockFetch }
  );
  assert.equal(testPushOk.status, 200);
  assert.equal(sentPushRequests.length, 2);

  nextPushStatus = 410;
  const testPushGone = await handleWorkerRequest(
    new Request('https://worker.test/api/v1/push/test', {
      method: 'POST',
      headers: { Origin: ORIGIN, Authorization: `Bearer ${ownerJwt}` },
    }),
    env,
    { nowMs: NOW_MS, jwksOverride, fetchImpl: mockFetch }
  );
  assert.equal(testPushGone.status, 502);
  // Inscrição foi revogada automaticamente após 410 Gone
  assert.notEqual(db.pushSubscriptions[0].revoked_at, null);
});
