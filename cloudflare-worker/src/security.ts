/**
 * Camada criptográfica e de segurança do Cloudflare Worker do PULSO.
 * Zero dependências externas — utiliza exclusivamente Web Crypto API nativa.
 *
 * Garantias:
 * 1. Tokens do iPhone têm 256 bits de entropia e são armazenados apenas como hash SHA-256.
 * 2. Credenciais na URL/query string são bloqueadas com erro explícito (HTTP 400).
 * 3. Comparação de hashes em tempo constante.
 * 4. Rotas do PULSO validam criptograficamente o Firebase ID Token (RS256) contra as
 *    chaves públicas oficiais do Google, exigindo aud, iss, exp, email_verified e e-mail da titular.
 */

export interface FirebaseJwtVerificationResult {
  valid: boolean;
  uid?: string;
  email?: string;
  reason?: string;
}

export interface VerifyFirebaseTokenOptions {
  projectId: string;
  authorizedEmail: string;
  nowMs?: number;
  fetchImpl?: typeof fetch;
  /** Permite injetar chaves JWK em testes automatizados determinísticos sem depender de rede. */
  jwksOverride?: Record<string, JsonWebKey>;
}

const GOOGLE_SECURETOKEN_JWK_URL =
  'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

const FORBIDDEN_URL_CREDENTIAL_PARAMS = new Set([
  'token',
  'access_token',
  'auth',
  'authorization',
  'key',
  'api_key',
  'apikey',
  'secret',
  'bearer',
  'device_token',
]);

let cachedJwks: { keys: Record<string, JsonWebKey>; expiresAtMs: number } | null = null;

export function hasForbiddenUrlCredentials(url: URL): boolean {
  for (const key of url.searchParams.keys()) {
    if (FORBIDDEN_URL_CREDENTIAL_PARAMS.has(key.trim().toLowerCase())) {
      return true;
    }
  }
  return false;
}

export function extractBearerToken(request: Request): string | null {
  const authHeader = request.headers.get('Authorization') ?? request.headers.get('authorization');
  if (!authHeader) return null;
  const match = authHeader.match(/^Bearer\s+([^\s]+)$/i);
  if (!match?.[1]) return null;
  const token = match[1].trim();
  return token.length > 0 ? token : null;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(input: string): Uint8Array {
  const normalized = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export async function sha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Comparação em tempo constante para hashes hexadecimais (proteção contra timing attacks).
 */
export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length || a.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Gera uma credencial criptograficamente segura de 256 bits para um dispositivo iPhone.
 * O plaintext é exibido uma única vez ao usuário; o D1 armazena apenas tokenHash.
 */
export async function generateDeviceToken(): Promise<{
  id: string;
  plaintextToken: string;
  tokenPrefix: string;
  tokenHash: string;
}> {
  const idBytes = new Uint8Array(9);
  const secretBytes = new Uint8Array(32);
  crypto.getRandomValues(idBytes);
  crypto.getRandomValues(secretBytes);

  const id = `tok_${bytesToHex(idBytes)}`;
  const plaintextToken = `pls_c6_${bytesToBase64Url(secretBytes)}`;
  const tokenPrefix = `${plaintextToken.slice(0, 12)}...`;
  const tokenHash = await sha256Hex(plaintextToken);

  return {
    id,
    plaintextToken,
    tokenPrefix,
    tokenHash,
  };
}

export function buildCorsHeaders(
  origin: string | null,
  allowedOriginsCsv: string | undefined
): Record<string, string> {
  const allowedList = (allowedOriginsCsv ?? '')
    .split(',')
    .map((item) => item.trim().replace(/\/+$/, ''))
    .filter((item) => item.length > 0);

  const normalizedOrigin = origin ? origin.trim().replace(/\/+$/, '') : null;
  const isAllowed = Boolean(normalizedOrigin && allowedList.includes(normalizedOrigin));

  const headers: Record<string, string> = {
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  };

  if (isAllowed && normalizedOrigin) {
    headers['Access-Control-Allow-Origin'] = normalizedOrigin;
    headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type';
    headers['Access-Control-Max-Age'] = '600';
  }

  return headers;
}

export function isOriginAllowed(
  origin: string | null,
  allowedOriginsCsv: string | undefined
): boolean {
  if (!origin) return true; // Requisições nativas (ex.: Atalhos iOS) não enviam cabeçalho Origin
  const allowedList = (allowedOriginsCsv ?? '')
    .split(',')
    .map((item) => item.trim().replace(/\/+$/, ''))
    .filter((item) => item.length > 0);
  return allowedList.includes(origin.trim().replace(/\/+$/, ''));
}

async function fetchGoogleJwks(
  fetchImpl: typeof fetch,
  nowMs: number
): Promise<Record<string, JsonWebKey>> {
  if (cachedJwks && cachedJwks.expiresAtMs > nowMs) {
    return cachedJwks.keys;
  }

  const response = await fetchImpl(GOOGLE_SECURETOKEN_JWK_URL, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`google_jwk_fetch_failed_${response.status}`);
  }

  const body = (await response.json()) as { keys?: Array<JsonWebKey & { kid?: string }> };
  const map: Record<string, JsonWebKey> = {};
  for (const key of body.keys ?? []) {
    if (key.kid) {
      map[key.kid] = key;
    }
  }

  const cacheControl = response.headers.get('cache-control') ?? '';
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const maxAgeSec = maxAgeMatch ? Number.parseInt(maxAgeMatch[1], 10) : 3600;
  const clampedTtlMs = Math.max(60, Math.min(maxAgeSec, 21600)) * 1000;

  cachedJwks = {
    keys: map,
    expiresAtMs: nowMs + clampedTtlMs,
  };

  return map;
}

export function clearJwksCacheForTests(): void {
  cachedJwks = null;
}

/**
 * Verifica criptograficamente um Firebase Auth ID Token (RS256) sem precisar de Admin SDK nem IAM.
 */
export async function verifyFirebaseIdToken(
  token: string,
  options: VerifyFirebaseTokenOptions
): Promise<FirebaseJwtVerificationResult> {
  const parts = token.split('.');
  if (parts.length !== 3) {
    return { valid: false, reason: 'malformed_jwt' };
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  let header: { alg?: string; kid?: string; typ?: string };
  let payload: {
    aud?: string;
    iss?: string;
    sub?: string;
    exp?: number;
    iat?: number;
    auth_time?: number;
    email?: string;
    email_verified?: boolean;
  };

  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64)));
    payload = JSON.parse(new TextDecoder().decode(base64UrlToBytes(payloadB64)));
  } catch {
    return { valid: false, reason: 'invalid_jwt_encoding' };
  }

  if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length === 0) {
    return { valid: false, reason: 'unsupported_jwt_header' };
  }

  const nowMs = options.nowMs ?? Date.now();
  const nowSec = Math.floor(nowMs / 1000);
  const expectedIssuer = `https://securetoken.google.com/${options.projectId}`;

  if (payload.aud !== options.projectId) {
    return { valid: false, reason: 'invalid_audience' };
  }
  if (payload.iss !== expectedIssuer) {
    return { valid: false, reason: 'invalid_issuer' };
  }
  if (typeof payload.sub !== 'string' || payload.sub.trim().length === 0 || payload.sub.length > 128) {
    return { valid: false, reason: 'invalid_subject' };
  }
  if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
    return { valid: false, reason: 'token_expired' };
  }
  if (typeof payload.iat !== 'number' || payload.iat > nowSec + 300) {
    return { valid: false, reason: 'invalid_iat' };
  }
  if (typeof payload.auth_time === 'number' && payload.auth_time > nowSec + 300) {
    return { valid: false, reason: 'invalid_auth_time' };
  }
  if (payload.email_verified !== true) {
    return { valid: false, reason: 'email_not_verified' };
  }
  if (
    typeof payload.email !== 'string' ||
    payload.email.trim().toLowerCase() !== options.authorizedEmail.trim().toLowerCase()
  ) {
    return { valid: false, reason: 'unauthorized_email' };
  }

  let jwks: Record<string, JsonWebKey>;
  try {
    jwks = options.jwksOverride ?? (await fetchGoogleJwks(options.fetchImpl ?? fetch, nowMs));
  } catch {
    return { valid: false, reason: 'jwks_unavailable' };
  }

  const jwk = jwks[header.kid];
  if (!jwk) {
    return { valid: false, reason: 'unknown_signing_key' };
  }

  try {
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signedData = new Uint8Array(new TextEncoder().encode(`${headerB64}.${payloadB64}`));
    const signatureBytes = new Uint8Array(base64UrlToBytes(signatureB64));

    const signatureValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      publicKey,
      signatureBytes,
      signedData
    );

    if (!signatureValid) {
      return { valid: false, reason: 'invalid_signature' };
    }
  } catch {
    return { valid: false, reason: 'signature_verification_error' };
  }

  return {
    valid: true,
    uid: payload.sub,
    email: payload.email,
  };
}
