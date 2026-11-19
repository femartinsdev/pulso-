/**
 * PULSO — Cloudflare Worker + D1 (Camada Gratuita)
 *
 * Rotas:
 * - POST   /api/v1/intake        (Auth: Token revogável do iPhone via Header Authorization: Bearer)
 * - GET    /api/v1/health        (Auth: Firebase Auth ID Token RS256 da titular)
 * - GET    /api/v1/pending       (Auth: Firebase Auth ID Token RS256 da titular)
 * - POST   /api/v1/ack           (Auth: Firebase Auth ID Token RS256 da titular)
 * - GET    /api/v1/tokens        (Auth: Firebase Auth ID Token RS256 da titular)
 * - POST   /api/v1/tokens        (Auth: Firebase Auth ID Token RS256 da titular)
 * - DELETE /api/v1/tokens/:id    (Auth: Firebase Auth ID Token RS256 da titular)
 * - GET    /api/v1/diagnostics   (Auth: Firebase Auth ID Token RS256 da titular)
 */

import { evaluateC6Notification, type IntakeRequestPayload } from './c6Parser.ts';
import {
  buildCorsHeaders,
  constantTimeEqualHex,
  extractBearerToken,
  generateDeviceToken,
  hasForbiddenUrlCredentials,
  isOriginAllowed,
  sha256Hex,
  verifyFirebaseIdToken,
} from './security.ts';

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<{ success: boolean; meta?: { changes?: number } }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export interface WorkerEnv {
  DB: D1DatabaseLike;
  FIREBASE_PROJECT_ID: string;
  AUTHORIZED_OWNER_EMAIL: string;
  ALLOWED_ORIGINS?: string;
}

export interface HandleRequestOptions {
  nowMs?: number;
  fetchImpl?: typeof fetch;
  jwksOverride?: Record<string, JsonWebKey>;
}

interface DeviceTokenRow {
  id: string;
  label: string;
  token_prefix: string;
  token_hash: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

interface IntakeEventRow {
  id: string;
  idempotency_key: string;
  token_id: string;
  bank_origin: string;
  raw_summary: string;
  merchant_name: string | null;
  proposed_description: string;
  proposed_amount_cents: number;
  proposed_type: 'income' | 'expense' | 'transfer';
  confidence: 'high' | 'ambiguous';
  ambiguity_reason: string | null;
  occurred_at: string;
  received_at: string;
  acked_at: string | null;
}

interface DeliveryLogRow {
  id: string;
  created_at: string;
  route: string;
  outcome: string;
  reason_code: string;
  summary: string | null;
  token_id: string | null;
  http_status: number;
}

const MAX_INTAKE_BODY_BYTES = 16 * 1024; // 16 KB
const RETENTION_ACKED_DAYS = 30;
const MAX_DIAGNOSTIC_LOG_ROWS = 200;

function jsonResponse(
  body: unknown,
  status: number,
  corsHeaders: Record<string, string>
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders,
    },
  });
}

function makeRandomId(prefix: string): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return `${prefix}_${hex}`;
}

async function appendDeliveryLog(
  db: D1DatabaseLike,
  entry: {
    nowIso: string;
    route: string;
    outcome: string;
    reasonCode: string;
    summary?: string | null;
    tokenId?: string | null;
    httpStatus: number;
  }
): Promise<void> {
  try {
    await db
      .prepare(
        `INSERT INTO delivery_logs (id, created_at, route, outcome, reason_code, summary, token_id, http_status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
      )
      .bind(
        makeRandomId('log'),
        entry.nowIso,
        entry.route,
        entry.outcome,
        entry.reasonCode,
        entry.summary ? entry.summary.slice(0, 140) : null,
        entry.tokenId ?? null,
        entry.httpStatus
      )
      .run();

    // Retenção leve para respeitar limites gratuitos do D1
    await db
      .prepare(
        `DELETE FROM delivery_logs
         WHERE id NOT IN (
           SELECT id FROM delivery_logs ORDER BY created_at DESC LIMIT ?
         )`
      )
      .bind(MAX_DIAGNOSTIC_LOG_ROWS)
      .run();
  } catch {
    // Falha de log não deve derrubar o fluxo principal nem expor detalhes internos
  }
}

async function cleanupOldAckedEvents(db: D1DatabaseLike, nowMs: number): Promise<void> {
  try {
    const cutoffIso = new Date(nowMs - RETENTION_ACKED_DAYS * 24 * 60 * 60 * 1000).toISOString();
    await db
      .prepare(`DELETE FROM intake_events WHERE acked_at IS NOT NULL AND acked_at < ?`)
      .bind(cutoffIso)
      .run();
  } catch {
    // Limpeza oportunista
  }
}

async function authenticateDeviceToken(
  db: D1DatabaseLike,
  plaintextToken: string
): Promise<DeviceTokenRow | null> {
  const candidateHash = await sha256Hex(plaintextToken);
  const activeTokens = await db
    .prepare(
      `SELECT id, label, token_prefix, token_hash, created_at, last_used_at, revoked_at
       FROM device_tokens
       WHERE revoked_at IS NULL`
    )
    .all<DeviceTokenRow>();

  let matched: DeviceTokenRow | null = null;
  for (const row of activeTokens.results ?? []) {
    if (constantTimeEqualHex(row.token_hash, candidateHash)) {
      matched = row;
    }
  }
  return matched;
}

async function authenticateFirebaseOwner(
  request: Request,
  env: WorkerEnv,
  options: HandleRequestOptions
) {
  const bearer = extractBearerToken(request);
  if (!bearer) {
    return { valid: false as const, reason: 'missing_authorization_header' };
  }
  return verifyFirebaseIdToken(bearer, {
    projectId: env.FIREBASE_PROJECT_ID,
    authorizedEmail: env.AUTHORIZED_OWNER_EMAIL,
    nowMs: options.nowMs,
    fetchImpl: options.fetchImpl,
    jwksOverride: options.jwksOverride,
  });
}

export async function handleWorkerRequest(
  request: Request,
  env: WorkerEnv,
  options: HandleRequestOptions = {}
): Promise<Response> {
  const url = new URL(request.url);
  const origin = request.headers.get('Origin');
  const corsHeaders = buildCorsHeaders(origin, env.ALLOWED_ORIGINS);
  const nowMs = options.nowMs ?? Date.now();
  const nowIso = new Date(nowMs).toISOString();

  // 1. CORS Preflight estrito
  if (request.method === 'OPTIONS') {
    if (origin && !isOriginAllowed(origin, env.ALLOWED_ORIGINS)) {
      return jsonResponse({ error: 'origin_not_allowed' }, 403, corsHeaders);
    }
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // 2. Bloqueio absoluto de credenciais na URL (query string)
  if (hasForbiddenUrlCredentials(url)) {
    await appendDeliveryLog(env.DB, {
      nowIso,
      route: url.pathname,
      outcome: 'rejected_auth',
      reasonCode: 'token_in_url_forbidden',
      summary: 'Credencial enviada na URL foi rejeitada por segurança',
      httpStatus: 400,
    });
    return jsonResponse(
      {
        ok: false,
        error: 'token_in_url_forbidden',
        message: 'Credenciais nunca podem ser enviadas na URL. Use o cabeçalho Authorization: Bearer.',
      },
      400,
      corsHeaders
    );
  }

  // --- ROTA DO IPHONE (ATALHOS iOS): POST /api/v1/intake ---
  if (url.pathname === '/api/v1/intake' && request.method === 'POST') {
    const deviceToken = extractBearerToken(request);
    if (!deviceToken) {
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: 'rejected_auth',
        reasonCode: 'missing_device_token',
        summary: 'Requisição sem cabeçalho Authorization: Bearer',
        httpStatus: 401,
      });
      return jsonResponse(
        {
          ok: false,
          error: 'missing_device_token',
          message: 'Cabeçalho Authorization: Bearer <token> obrigatório.',
        },
        401,
        corsHeaders
      );
    }

    const tokenRow = await authenticateDeviceToken(env.DB, deviceToken);
    if (!tokenRow) {
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: 'rejected_auth',
        reasonCode: 'invalid_or_revoked_token',
        summary: 'Token do dispositivo inválido ou revogado',
        httpStatus: 401,
      });
      return jsonResponse(
        {
          ok: false,
          error: 'invalid_or_revoked_token',
          message: 'Credencial inválida ou revogada.',
        },
        401,
        corsHeaders
      );
    }

    // Atualiza last_used_at
    await env.DB.prepare(`UPDATE device_tokens SET last_used_at = ? WHERE id = ?`)
      .bind(nowIso, tokenRow.id)
      .run();

    // Limite de tamanho do corpo JSON
    const rawBody = await request.text();
    const byteSize = new TextEncoder().encode(rawBody).length;
    if (byteSize === 0 || byteSize > MAX_INTAKE_BODY_BYTES) {
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: 'error',
        reasonCode: 'payload_size_invalid',
        summary: `Tamanho inválido (${byteSize} bytes)`,
        tokenId: tokenRow.id,
        httpStatus: 400,
      });
      return jsonResponse(
        { ok: false, error: 'payload_size_invalid', message: 'Corpo da requisição vazio ou acima de 16 KB.' },
        400,
        corsHeaders
      );
    }

    let payload: IntakeRequestPayload;
    try {
      const parsed: unknown = JSON.parse(rawBody);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('not_an_object');
      }
      payload = parsed as IntakeRequestPayload;
    } catch {
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: 'error',
        reasonCode: 'invalid_json',
        summary: 'JSON malformado recebido do Atalho',
        tokenId: tokenRow.id,
        httpStatus: 400,
      });
      return jsonResponse(
        { ok: false, error: 'invalid_json', message: 'Envie um objeto JSON válido com Content-Type: application/json.' },
        400,
        corsHeaders
      );
    }

    const evaluation = evaluateC6Notification(payload, nowIso);
    if (!evaluation.accepted || !evaluation.event) {
      const code = evaluation.ignoredCode ?? 'ignored_insufficient_data';
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: code,
        reasonCode: code,
        summary: evaluation.safeDiagnosticSummary ?? evaluation.reasonMessage,
        tokenId: tokenRow.id,
        httpStatus: 200,
      });
      return jsonResponse(
        {
          ok: true,
          status: 'ignored',
          reasonCode: code,
          message: evaluation.reasonMessage,
        },
        200,
        corsHeaders
      );
    }

    const evt = evaluation.event;
    const eventId = makeRandomId('evt');

    const insertResult = await env.DB.prepare(
      `INSERT OR IGNORE INTO intake_events (
         id, idempotency_key, token_id, bank_origin, raw_summary, merchant_name,
         proposed_description, proposed_amount_cents, proposed_type, confidence,
         ambiguity_reason, occurred_at, received_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        eventId,
        evt.idempotencyKey,
        tokenRow.id,
        evt.bankOrigin,
        evt.rawSummary,
        evt.merchantName,
        evt.proposedDescription,
        evt.proposedAmountCents,
        evt.proposedType,
        evt.confidence,
        evt.ambiguityReason,
        evt.occurredAt,
        nowIso
      )
      .run();

    const changes = insertResult.meta?.changes ?? 0;
    if (changes === 0) {
      await appendDeliveryLog(env.DB, {
        nowIso,
        route: '/api/v1/intake',
        outcome: 'duplicate',
        reasonCode: 'idempotency_conflict',
        summary: evaluation.safeDiagnosticSummary ?? evt.proposedDescription,
        tokenId: tokenRow.id,
        httpStatus: 200,
      });
      return jsonResponse(
        {
          ok: true,
          status: 'duplicate',
          idempotencyKey: evt.idempotencyKey,
          message: 'Notificação já registrada anteriormente (idempotência garantida).',
        },
        200,
        corsHeaders
      );
    }

    await appendDeliveryLog(env.DB, {
      nowIso,
      route: '/api/v1/intake',
      outcome: 'accepted',
      reasonCode: evt.confidence === 'high' ? 'c6_high_confidence' : evt.ambiguityReason ?? 'c6_ambiguous',
      summary: evaluation.safeDiagnosticSummary ?? evt.proposedDescription,
      tokenId: tokenRow.id,
      httpStatus: 201,
    });

    await cleanupOldAckedEvents(env.DB, nowMs);

    return jsonResponse(
      {
        ok: true,
        status: 'queued',
        eventId,
        idempotencyKey: evt.idempotencyKey,
        confidence: evt.confidence,
        ambiguityReason: evt.ambiguityReason,
        proposedType: evt.proposedType,
        proposedAmountCents: evt.proposedAmountCents,
        proposedDescription: evt.proposedDescription,
      },
      201,
      corsHeaders
    );
  }

  // --- ROTAS ADMINISTRATIVAS E DE SYNC DO PULSO (Exigem Origin permitida + Firebase JWT RS256) ---
  if (origin && !isOriginAllowed(origin, env.ALLOWED_ORIGINS)) {
    return jsonResponse({ ok: false, error: 'origin_not_allowed' }, 403, corsHeaders);
  }

  const ownerAuth = await authenticateFirebaseOwner(request, env, options);
  if (!ownerAuth.valid) {
    return jsonResponse(
      {
        ok: false,
        error: 'unauthorized_firebase_session',
        reason: ownerAuth.reason ?? 'invalid_token',
      },
      401,
      corsHeaders
    );
  }

  // GET /api/v1/health
  if (url.pathname === '/api/v1/health' && request.method === 'GET') {
    const pendingCountRow = await env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM intake_events WHERE acked_at IS NULL`
    ).first<{ cnt: number }>();
    const activeTokensRow = await env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM device_tokens WHERE revoked_at IS NULL`
    ).first<{ cnt: number }>();

    return jsonResponse(
      {
        ok: true,
        service: 'pulso-c6-intake',
        ownerEmail: ownerAuth.email,
        supportedBank: 'c6_bank',
        pendingCount: Number(pendingCountRow?.cnt ?? 0),
        activeTokensCount: Number(activeTokensRow?.cnt ?? 0),
        serverTimeIso: nowIso,
      },
      200,
      corsHeaders
    );
  }

  // GET /api/v1/pending
  if (url.pathname === '/api/v1/pending' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, idempotency_key, token_id, bank_origin, raw_summary, merchant_name,
              proposed_description, proposed_amount_cents, proposed_type, confidence,
              ambiguity_reason, occurred_at, received_at
       FROM intake_events
       WHERE acked_at IS NULL
       ORDER BY occurred_at ASC, received_at ASC
       LIMIT 100`
    ).all<IntakeEventRow>();

    return jsonResponse(
      {
        ok: true,
        events: (rows.results ?? []).map((r) => ({
          id: r.id,
          idempotencyKey: r.idempotency_key,
          bankOrigin: r.bank_origin,
          rawSummary: r.raw_summary,
          merchantName: r.merchant_name,
          proposedDescription: r.proposed_description,
          proposedAmountCents: Number(r.proposed_amount_cents),
          proposedType: r.proposed_type,
          confidence: r.confidence,
          ambiguityReason: r.ambiguity_reason,
          occurredAt: r.occurred_at,
          receivedAt: r.received_at,
        })),
        serverTimeIso: nowIso,
      },
      200,
      corsHeaders
    );
  }

  // POST /api/v1/ack
  if (url.pathname === '/api/v1/ack' && request.method === 'POST') {
    let body: {
      items?: Array<{ id: string; targetCollection?: string; docId?: string }>;
      eventIds?: string[];
    };
    try {
      body = (await request.json()) as typeof body;
    } catch {
      return jsonResponse({ ok: false, error: 'invalid_json' }, 400, corsHeaders);
    }

    const ackItems: Array<{ id: string; targetCollection?: string; docId?: string }> =
      Array.isArray(body.items)
        ? body.items
        : Array.isArray(body.eventIds)
          ? body.eventIds.map((id) => ({ id }))
          : [];

    if (ackItems.length === 0 || ackItems.length > 200) {
      return jsonResponse({ ok: false, error: 'invalid_ack_batch' }, 400, corsHeaders);
    }

    let ackedCount = 0;
    for (const item of ackItems) {
      if (!item || typeof item.id !== 'string' || item.id.trim().length === 0) continue;
      const res = await env.DB.prepare(
        `UPDATE intake_events
         SET acked_at = ?, ack_target_collection = ?, ack_doc_id = ?
         WHERE id = ? AND acked_at IS NULL`
      )
        .bind(
          nowIso,
          typeof item.targetCollection === 'string' ? item.targetCollection.slice(0, 32) : 'firestore',
          typeof item.docId === 'string' ? item.docId.slice(0, 128) : null,
          item.id.trim()
        )
        .run();
      ackedCount += res.meta?.changes ?? 0;
    }

    return jsonResponse({ ok: true, ackedCount, serverTimeIso: nowIso }, 200, corsHeaders);
  }

  // GET /api/v1/tokens
  if (url.pathname === '/api/v1/tokens' && request.method === 'GET') {
    const rows = await env.DB.prepare(
      `SELECT id, label, token_prefix, created_at, last_used_at, revoked_at
       FROM device_tokens
       ORDER BY created_at DESC
       LIMIT 30`
    ).all<Omit<DeviceTokenRow, 'token_hash'>>();

    return jsonResponse(
      {
        ok: true,
        tokens: (rows.results ?? []).map((t) => ({
          id: t.id,
          label: t.label,
          tokenPrefix: t.token_prefix,
          createdAt: t.created_at,
          lastUsedAt: t.last_used_at,
          revokedAt: t.revoked_at,
          active: t.revoked_at === null,
        })),
      },
      200,
      corsHeaders
    );
  }

  // POST /api/v1/tokens
  if (url.pathname === '/api/v1/tokens' && request.method === 'POST') {
    let body: { label?: string } = {};
    try {
      body = (await request.json()) as { label?: string };
    } catch {
      body = {};
    }

    const label = (body.label ?? 'iPhone Principal').trim().slice(0, 60) || 'iPhone Principal';
    const generated = await generateDeviceToken();

    await env.DB.prepare(
      `INSERT INTO device_tokens (id, label, token_prefix, token_hash, created_at)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(generated.id, label, generated.tokenPrefix, generated.tokenHash, nowIso)
      .run();

    await appendDeliveryLog(env.DB, {
      nowIso,
      route: '/api/v1/tokens',
      outcome: 'token_created',
      reasonCode: 'device_token_issued',
      summary: `Credencial criada: ${label} (${generated.tokenPrefix})`,
      tokenId: generated.id,
      httpStatus: 201,
    });

    return jsonResponse(
      {
        ok: true,
        token: {
          id: generated.id,
          label,
          tokenPrefix: generated.tokenPrefix,
          createdAt: nowIso,
          lastUsedAt: null,
          revokedAt: null,
          active: true,
        },
        /** Retornado uma única vez — nunca mais pode ser recuperado. */
        plaintextToken: generated.plaintextToken,
      },
      201,
      corsHeaders
    );
  }

  // DELETE /api/v1/tokens/:id
  const deleteTokenMatch = url.pathname.match(/^\/api\/v1\/tokens\/([a-zA-Z0-9_-]{4,64})$/);
  if (deleteTokenMatch && request.method === 'DELETE') {
    const tokenId = deleteTokenMatch[1];
    const res = await env.DB.prepare(
      `UPDATE device_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`
    )
      .bind(nowIso, tokenId)
      .run();

    if ((res.meta?.changes ?? 0) === 0) {
      return jsonResponse({ ok: false, error: 'token_not_found_or_already_revoked' }, 404, corsHeaders);
    }

    await appendDeliveryLog(env.DB, {
      nowIso,
      route: `/api/v1/tokens/${tokenId}`,
      outcome: 'token_revoked',
      reasonCode: 'device_token_revoked',
      summary: `Credencial revogada imediatamente (${tokenId})`,
      tokenId,
      httpStatus: 200,
    });

    return jsonResponse({ ok: true, revokedId: tokenId, revokedAt: nowIso }, 200, corsHeaders);
  }

  // GET /api/v1/diagnostics
  if (url.pathname === '/api/v1/diagnostics' && request.method === 'GET') {
    const logs = await env.DB.prepare(
      `SELECT id, created_at, route, outcome, reason_code, summary, token_id, http_status
       FROM delivery_logs
       ORDER BY created_at DESC
       LIMIT 50`
    ).all<DeliveryLogRow>();

    const pendingCountRow = await env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM intake_events WHERE acked_at IS NULL`
    ).first<{ cnt: number }>();

    const totalAckedRow = await env.DB.prepare(
      `SELECT COUNT(*) AS cnt FROM intake_events WHERE acked_at IS NOT NULL`
    ).first<{ cnt: number }>();

    return jsonResponse(
      {
        ok: true,
        pendingInQueueCount: Number(pendingCountRow?.cnt ?? 0),
        totalSyncedCount: Number(totalAckedRow?.cnt ?? 0),
        logs: (logs.results ?? []).map((row) => ({
          id: row.id,
          createdAt: row.created_at,
          route: row.route,
          outcome: row.outcome,
          reasonCode: row.reason_code,
          summary: row.summary,
          tokenId: row.token_id,
          httpStatus: Number(row.http_status),
        })),
        serverTimeIso: nowIso,
      },
      200,
      corsHeaders
    );
  }

  return jsonResponse({ ok: false, error: 'not_found' }, 404, corsHeaders);
}

export default {
  fetch(request: Request, env: WorkerEnv): Promise<Response> {
    return handleWorkerRequest(request, env);
  },
};
