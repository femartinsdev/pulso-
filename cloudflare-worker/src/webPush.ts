/**
 * PULSO 2.0 — Web Push (RFC 8292 VAPID ES256 + RFC 8291 aes128gcm) em Web Crypto puro.
 *
 * Sem dependências Node-only: funciona nativamente no runtime Cloudflare Workers
 * e em Node.js 20+ para testes automatizados locais.
 *
 * Regras de copy e segurança:
 * - Nunca afirma que o lançamento já foi sincronizado no Firestore antes do app abrir;
 *   sempre usa a linguagem honesta de "movimentação detectada" aguardando sincronização/categorização.
 * - Modo privacidade oculta valores monetários e nomes de estabelecimentos.
 * - Rotação determinística anti-repetição para os tons: sarcastic (padrão), funny e discreet.
 */

export type PushTone = 'sarcastic' | 'funny' | 'discreet';

export interface PushPreferences {
  enabled: boolean;
  tone: PushTone;
  privacyMode: boolean;
  notifyIncome: boolean;
  notifyExpense: boolean;
  notifyCategorization: boolean;
  lastPhraseIndex: number;
  updatedAt: string;
}

export interface StoredPushSubscription {
  id: string;
  endpoint: string;
  p256dh: string;
  auth: string;
  userAgent: string | null;
}

export interface VapidConfig {
  publicKey: string;
  privateKey: string;
  subject: string;
}

export interface PushMessagePayload {
  title: string;
  body: string;
  tag: string;
  url: string;
  eventId?: string;
  tone: PushTone;
  privacyMode: boolean;
}

export interface PushSendResult {
  ok: boolean;
  status: number;
  expired: boolean;
  error?: string;
}

export const DEFAULT_PUSH_PREFERENCES: Omit<PushPreferences, 'updatedAt'> = {
  enabled: true,
  tone: 'sarcastic',
  privacyMode: false,
  notifyIncome: true,
  notifyExpense: true,
  notifyCategorization: true,
  lastPhraseIndex: -1,
};

const TEXT_ENCODER = new TextEncoder();

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function fromBase64Url(input: string): Uint8Array {
  const normalized = input.trim().replace(/-/g, '+').replace(/_/g, '/');
  const padLen = (4 - (normalized.length % 4)) % 4;
  const padded = normalized + '='.repeat(padLen);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function isValidPushTone(value: unknown): value is PushTone {
  return value === 'sarcastic' || value === 'funny' || value === 'discreet';
}

export function isValidVapidConfig(config: Partial<VapidConfig>): config is VapidConfig {
  if (!config.publicKey || !config.privateKey || !config.subject) return false;
  try {
    const pub = fromBase64Url(config.publicKey);
    const priv = fromBase64Url(config.privateKey);
    const subjectOk =
      config.subject.startsWith('mailto:') || config.subject.startsWith('https://');
    return pub.length === 65 && pub[0] === 0x04 && priv.length === 32 && subjectOk;
  } catch {
    return false;
  }
}

export function isValidPushEndpoint(endpoint: string): boolean {
  try {
    const url = new URL(endpoint);
    return url.protocol === 'https:' && url.hostname.length > 0 && endpoint.length <= 2048;
  } catch {
    return false;
  }
}

export function isValidPushKeys(p256dh: string, auth: string): boolean {
  try {
    const pub = fromBase64Url(p256dh);
    const authBytes = fromBase64Url(auth);
    return pub.length === 65 && pub[0] === 0x04 && authBytes.length >= 16 && authBytes.length <= 32;
  } catch {
    return false;
  }
}

function formatCentsBRLSimple(cents: number): string {
  const abs = Math.abs(Math.round(cents));
  const reais = Math.floor(abs / 100);
  const centavos = String(abs % 100).padStart(2, '0');
  const reaisStr = String(reais).replace(/\B(?=(\d{3})+(?!\d))/g, '.');
  return `R$ ${reaisStr},${centavos}`;
}

interface CopyTemplate {
  title: string;
  body: (amount: string, place: string) => string;
}

const EXPENSE_TEMPLATES: Record<PushTone, CopyTemplate[]> = {
  sarcastic: [
    {
      title: 'PULSO · Mais uma saída detectada',
      body: (v, m) => `${v} em ${m} no C6 Bank. O saldo pediu um minuto de silêncio — abra para categorizar.`,
    },
    {
      title: 'PULSO · Cartão trabalhando pesado',
      body: (v, m) => `Detectei ${v} em ${m}. Foi necessidade ou "bobeira"? Abra o PULSO e confesse na categoria.`,
    },
    {
      title: 'PULSO · Alerta de carteira leve',
      body: (v, m) => `Saída detectada: ${v} em ${m} (C6 Bank). Toque para sincronizar e categorizar.`,
    },
    {
      title: 'PULSO · O Pix não dorme',
      body: (v, m) => `${v} saindo em ${m}. Já deixei na fila — abra para colocar a etiqueta certa.`,
    },
  ],
  funny: [
    {
      title: 'PULSO · Opa, gasto detectado!',
      body: (v, m) => `Piscou e lá se foram ${v} em ${m} no C6 Bank. Toque para sincronizar e categorizar.`,
    },
    {
      title: 'PULSO · Registro quentinho do C6',
      body: (v, m) => `Detectei uma saída de ${v} em ${m}. Bora escolher a categoria antes que você esqueça?`,
    },
    {
      title: 'PULSO · Dinheiro em movimento',
      body: (v, m) => `${v} em ${m} capturado pelo receptor. Abra o PULSO para classificar rapidinho.`,
    },
    {
      title: 'PULSO · Missão categoria',
      body: (v, m) => `Nova saída de ${v} em ${m} detectada. Um toque e ela já entra certinha no seu extrato.`,
    },
  ],
  discreet: [
    {
      title: 'PULSO · Nova saída detectada',
      body: (v, m) => `Saída de ${v} em ${m} (C6 Bank). Abra para sincronizar e categorizar.`,
    },
    {
      title: 'PULSO · Movimentação no C6 Bank',
      body: (v, m) => `${v} em ${m} detectado. Toque para sincronizar com seu extrato.`,
    },
    {
      title: 'PULSO · Lançamento aguardando categoria',
      body: (v, m) => `Saída de ${v} em ${m}. Abra o PULSO para revisar e classificar.`,
    },
  ],
};

const INCOME_TEMPLATES: Record<PushTone, CopyTemplate[]> = {
  sarcastic: [
    {
      title: 'PULSO · Olha só, entrou dinheiro!',
      body: (v, m) => `Entrada de ${v} (${m}) detectada no C6 Bank. Aproveite antes do próximo Pix — toque para categorizar.`,
    },
    {
      title: 'PULSO · Raro momento de paz no saldo',
      body: (v, m) => `Detectei +${v} (${m}). Abra o PULSO para sincronizar e registrar essa vitória.`,
    },
    {
      title: 'PULSO · Saldo respirando aliviado',
      body: (v, m) => `Entrada detectada: ${v} (${m}) no C6 Bank. Toque para classificar no extrato.`,
    },
  ],
  funny: [
    {
      title: 'PULSO · Opa, caiu na conta!',
      body: (v, m) => `Entrada de ${v} (${m}) detectada no C6 Bank. Abra o PULSO para sincronizar e celebrar.`,
    },
    {
      title: 'PULSO · Dinheiro entrando!',
      body: (v, m) => `Detectei +${v} (${m}). Toque para puxar pro extrato e escolher a categoria.`,
    },
    {
      title: 'PULSO · Boa notícia no C6 Bank',
      body: (v, m) => `Entrada de ${v} (${m}) na fila de sincronização. Abra para confirmar.`,
    },
  ],
  discreet: [
    {
      title: 'PULSO · Nova entrada detectada',
      body: (v, m) => `Entrada de ${v} (${m}) no C6 Bank. Abra para sincronizar e categorizar.`,
    },
    {
      title: 'PULSO · Crédito detectado no C6 Bank',
      body: (v, m) => `${v} (${m}) aguardando sincronização. Toque para abrir o PULSO.`,
    },
  ],
};

const PRIVACY_TEMPLATES: Record<PushTone, Array<{ title: string; body: string }>> = {
  sarcastic: [
    {
      title: 'PULSO · Movimentação detectada',
      body: 'Seu C6 Bank se mexeu. Valores ocultos por privacidade — abra para ver o estrago e categorizar.',
    },
    {
      title: 'PULSO · Novidade no C6 Bank',
      body: 'Nova movimentação detectada na fila. Toque para sincronizar e dar um nome a isso.',
    },
    {
      title: 'PULSO · Fila esperando você',
      body: 'Detectei atividade no C6 Bank (modo discreto ativo). Abra o PULSO para classificar.',
    },
  ],
  funny: [
    {
      title: 'PULSO · Opa, movimentação nova!',
      body: 'O C6 Bank mandou sinal. Detalhes ocultos no modo privacidade — abra para sincronizar.',
    },
    {
      title: 'PULSO · Tem novidade na fila',
      body: 'Movimentação detectada no C6 Bank. Toque para abrir o PULSO e categorizar.',
    },
    {
      title: 'PULSO · Extrato te chamando',
      body: 'Detectei uma nova movimentação. Abra o PULSO para puxar e classificar.',
    },
  ],
  discreet: [
    {
      title: 'PULSO · Nova movimentação detectada',
      body: 'Há uma movimentação do C6 Bank aguardando sincronização e categorização.',
    },
    {
      title: 'PULSO · Atualização disponível',
      body: 'Nova movimentação detectada. Abra o aplicativo para sincronizar seu extrato.',
    },
  ],
};

export function pickNextPhraseIndex(poolLength: number, lastIndex: number): number {
  if (poolLength <= 1) return 0;
  if (!Number.isFinite(lastIndex) || lastIndex < 0) return 0;
  return (Math.floor(lastIndex) + 1) % poolLength;
}

export function buildPushCopyForEvent(input: {
  eventId: string;
  proposedType: 'income' | 'expense' | 'transfer';
  proposedAmountCents: number;
  proposedDescription: string;
  merchantName: string | null;
  tone: PushTone;
  privacyMode: boolean;
  lastPhraseIndex: number;
}): { payload: PushMessagePayload; nextPhraseIndex: number } {
  const tone: PushTone = isValidPushTone(input.tone) ? input.tone : 'sarcastic';
  const targetUrl = '/?from=push&sync=1';

  if (input.privacyMode) {
    const pool = PRIVACY_TEMPLATES[tone];
    const nextIdx = pickNextPhraseIndex(pool.length, input.lastPhraseIndex);
    const tpl = pool[nextIdx];
    return {
      nextPhraseIndex: nextIdx,
      payload: {
        title: tpl.title,
        body: tpl.body,
        tag: `pulso-evt-${input.eventId}`,
        url: targetUrl,
        eventId: input.eventId,
        tone,
        privacyMode: true,
      },
    };
  }

  const amount = formatCentsBRLSimple(input.proposedAmountCents);
  const place = (input.merchantName || input.proposedDescription || 'C6 Bank').trim().slice(0, 60);
  const pool = input.proposedType === 'income' ? INCOME_TEMPLATES[tone] : EXPENSE_TEMPLATES[tone];
  const nextIdx = pickNextPhraseIndex(pool.length, input.lastPhraseIndex);
  const tpl = pool[nextIdx];

  return {
    nextPhraseIndex: nextIdx,
    payload: {
      title: tpl.title,
      body: tpl.body(amount, place),
      tag: `pulso-evt-${input.eventId}`,
      url: targetUrl,
      eventId: input.eventId,
      tone,
      privacyMode: false,
    },
  };
}

export function buildTestPushPayload(tone: PushTone, privacyMode: boolean): PushMessagePayload {
  const safeTone = isValidPushTone(tone) ? tone : 'sarcastic';
  if (privacyMode) {
    return {
      title: 'PULSO · Teste de notificação (privado)',
      body: 'Notificação real recebida no iPhone com modo privacidade ativo. Nenhum valor é exibido.',
      tag: 'pulso-test-push',
      url: '/?from=push&sync=1',
      tone: safeTone,
      privacyMode: true,
    };
  }

  const bodyByTone: Record<PushTone, string> = {
    sarcastic:
      'Teste concluído. Agora o PULSO já pode julgar seus gastos do C6 Bank direto na tela bloqueada.',
    funny:
      'Teste recebido com sucesso! Quando o C6 Bank apitar, o PULSO já te avisa por aqui.',
    discreet:
      'Teste de notificação confirmado. Novas movimentações detectadas do C6 Bank serão exibidas aqui.',
  };

  return {
    title: 'PULSO · Notificação de teste ativa',
    body: bodyByTone[safeTone],
    tag: 'pulso-test-push',
    url: '/?from=push&sync=1',
    tone: safeTone,
    privacyMode: false,
  };
}

/**
 * Converte par de chaves VAPID raw base64url (padrão `web-push generate-vapid-keys`)
 * em JWK EC P-256 para assinar JWT ES256 via Web Crypto API.
 */
async function importVapidPrivateKey(publicKeyB64: string, privateKeyB64: string): Promise<CryptoKey> {
  const pubBytes = fromBase64Url(publicKeyB64);
  const privBytes = fromBase64Url(privateKeyB64);
  if (pubBytes.length !== 65 || pubBytes[0] !== 0x04 || privBytes.length !== 32) {
    throw new Error('invalid_vapid_key_format');
  }

  const x = toBase64Url(pubBytes.slice(1, 33));
  const y = toBase64Url(pubBytes.slice(33, 65));
  const d = toBase64Url(privBytes);

  return crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      x,
      y,
      d,
      ext: false,
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

/**
 * Cria o cabeçalho Authorization: vapid t=<jwt>, k=<publicKey> (RFC 8292).
 */
export async function createVapidAuthorizationHeader(
  endpoint: string,
  vapid: VapidConfig,
  nowMs = Date.now()
): Promise<string> {
  const audience = new URL(endpoint).origin;
  const exp = Math.floor(nowMs / 1000) + 12 * 60 * 60; // 12h

  const headerB64 = toBase64Url(TEXT_ENCODER.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payloadB64 = toBase64Url(
    TEXT_ENCODER.encode(JSON.stringify({ aud: audience, exp, sub: vapid.subject }))
  );
  const signingInput = `${headerB64}.${payloadB64}`;

  const privateKey = await importVapidPrivateKey(vapid.publicKey, vapid.privateKey);
  const sigBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    TEXT_ENCODER.encode(signingInput)
  );
  // Web Crypto ECDSA retorna assinatura no formato IEEE P1363 (r || s, 64 bytes) — exatamente o padrão JWS ES256.
  const sigB64 = toBase64Url(new Uint8Array(sigBuf));

  return `vapid t=${signingInput}.${sigB64}, k=${vapid.publicKey}`;
}

async function hkdfDerive(
  salt: Uint8Array,
  ikm: Uint8Array,
  info: Uint8Array,
  lengthBytes: number
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', toArrayBuffer(ikm), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info),
    },
    key,
    lengthBytes * 8
  );
  return new Uint8Array(bits);
}

/**
 * Criptografa o payload JSON no formato padrão RFC 8291 (`aes128gcm`),
 * suportado pelo Apple Push Service (Safari/iOS 16.4+ PWA) e demais push services.
 */
export async function encryptWebPushPayloadAes128Gcm(
  plaintextJson: string,
  uaPublicKeyB64: string,
  authSecretB64: string
): Promise<Uint8Array> {
  const uaPublicBytes = fromBase64Url(uaPublicKeyB64);
  const authSecretBytes = fromBase64Url(authSecretB64);

  if (uaPublicBytes.length !== 65 || uaPublicBytes[0] !== 0x04) {
    throw new Error('invalid_subscription_p256dh');
  }
  if (authSecretBytes.length < 16) {
    throw new Error('invalid_subscription_auth');
  }

  // 1. Par de chaves efêmero P-256 do servidor (AS)
  const serverKeyPair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const asPublicBytes = new Uint8Array(
    await crypto.subtle.exportKey('raw', serverKeyPair.publicKey)
  );

  // 2. Importa chave pública do dispositivo (UA) e deriva ECDH shared secret
  const uaPublicKey = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(uaPublicBytes),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const sharedSecret = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: uaPublicKey },
      serverKeyPair.privateKey,
      256
    )
  );

  // 3. IKM via HKDF(salt=auth_secret, ikm=ecdh_secret, info="WebPush: info\0" || ua_public || as_public, L=32)
  const keyInfo = concatBytes(
    TEXT_ENCODER.encode('WebPush: info\0'),
    uaPublicBytes,
    asPublicBytes
  );
  const ikm = await hkdfDerive(authSecretBytes, sharedSecret, keyInfo, 32);

  // 4. Salt aleatório de 16 bytes -> CEK (16 bytes) e Nonce (12 bytes)
  const salt = new Uint8Array(16);
  crypto.getRandomValues(salt);

  const cek = await hkdfDerive(
    salt,
    ikm,
    TEXT_ENCODER.encode('Content-Encoding: aes128gcm\0'),
    16
  );
  const nonce = await hkdfDerive(
    salt,
    ikm,
    TEXT_ENCODER.encode('Content-Encoding: nonce\0'),
    12
  );

  // 5. Plaintext + delimitador final 0x02 (RFC 8188)
  const plaintextBytes = TEXT_ENCODER.encode(plaintextJson);
  const paddedPlaintext = concatBytes(plaintextBytes, new Uint8Array([0x02]));

  const aesKey = await crypto.subtle.importKey('raw', toArrayBuffer(cek), 'AES-GCM', false, [
    'encrypt',
  ]);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: toArrayBuffer(nonce), tagLength: 128 },
      aesKey,
      toArrayBuffer(paddedPlaintext)
    )
  );

  // 6. Cabeçalho binário aes128gcm: salt(16) || rs(4, BE=4096) || idlen(1, 65) || keyid(65)
  const recordSize = new Uint8Array(4);
  new DataView(recordSize.buffer).setUint32(0, 4096, false);
  const idLen = new Uint8Array([asPublicBytes.length]);

  return concatBytes(salt, recordSize, idLen, asPublicBytes, ciphertext);
}

/**
 * Envia uma notificação Web Push criptografada (RFC 8291 + RFC 8292) para o Push Service.
 * Nunca loga ou expõe chaves privadas.
 */
export async function sendEncryptedWebPush(
  subscription: StoredPushSubscription,
  payload: PushMessagePayload,
  vapid: VapidConfig,
  options: { fetchImpl?: typeof fetch; nowMs?: number; ttlSeconds?: number } = {}
): Promise<PushSendResult> {
  const fetchFn = options.fetchImpl ?? fetch;
  const ttlSeconds = options.ttlSeconds ?? 3600;

  try {
    const encryptedBody = await encryptWebPushPayloadAes128Gcm(
      JSON.stringify(payload),
      subscription.p256dh,
      subscription.auth
    );
    const authorization = await createVapidAuthorizationHeader(
      subscription.endpoint,
      vapid,
      options.nowMs
    );

    const response = await fetchFn(subscription.endpoint, {
      method: 'POST',
      headers: {
        Authorization: authorization,
        'Content-Encoding': 'aes128gcm',
        'Content-Type': 'application/octet-stream',
        TTL: String(ttlSeconds),
        Urgency: 'high',
      },
      body: toArrayBuffer(encryptedBody),
    });

    const expired = response.status === 404 || response.status === 410;
    if (response.ok || response.status === 201 || response.status === 202) {
      return { ok: true, status: response.status, expired: false };
    }

    return {
      ok: false,
      status: response.status,
      expired,
      error: `push_service_http_${response.status}`,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      expired: false,
      error: err instanceof Error ? err.message : 'push_send_failed',
    };
  }
}
