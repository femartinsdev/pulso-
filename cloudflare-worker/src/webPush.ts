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

type ValueTier = 'small' | 'medium' | 'large';

/**
 * Copys curtinhas na tela bloqueada: uma frase e, em linha separada,
 * somente o valor. O sistema operacional exibe a identidade do PWA.
 * Nenhum dado de estabelecimento, CPF/CNPJ ou descrição bancária é exposto.
 */
const INCOME_PHRASES: Record<PushTone, Record<ValueTier, string[]>> = {
  sarcastic: {
    small: [
      'Olha quem resolveu aparecer... O DINHEIRO! 💸',
      'Caiu um troquinho. Já dá pra respirar, né?',
      'Opa! A pobreza deu um passinho pra trás.',
      'Milagre! O saldo resolveu crescer.',
      'É pouco, mas já dá pra se achar rico por 5 minutos.',
    ],
    medium: [
      'AÍ SIM, PORRA! Agora começou a melhorar!',
      'Ó o dinheiro chegando, meu patrão!',
      'Recebeu Pix? Hoje o universo foi generoso.',
      'O saldo tava triste. Agora tá até sorrindo.',
      'Tá entrando grana, hein? Continua assim, filho!',
    ],
    large: [
      'CARALHO, TÁ RICO, HEIN?! 💸',
      'Calma, milionário! Lembra que os boletos existem.',
      'QUE DINHEIRO GOSTOSO, MEU AMIGO!',
      'Opa, magnata! O saldo até levantou pra aplaudir.',
      'RESPEITA O HOMEM! Hoje a grana veio de terno!',
    ],
  },
  funny: {
    small: ['Olha o troquinho chegando! 🪙', 'Tem visita nova na carteira!', 'O saldo ganhou um cafezinho!'],
    medium: ['Dinheiro na conta! Aí sim! 💸', 'Boa! O saldo tá sorrindo.', 'Hoje teve vitória financeira!'],
    large: ['Olha o magnata passando! 💰', 'Hoje o saldo tá fazendo festa!', 'Agora sim, patrão!'],
  },
  discreet: {
    small: ['Nova entrada recebida'],
    medium: ['Entrada registrada'],
    large: ['Nova entrada recebida'],
  },
};

const EXPENSE_PHRASES: Record<PushTone, Record<ValueTier, string[]>> = {
  sarcastic: {
    small: [
      'Lá se foi um troquinho. Pequeno, mas foi.',
      'Mais uma mordidinha no saldo, hein, filho?',
      'O dinheiro mal chegou e você já mandou embora?',
      'Olha a carteira emagrecendo sem academia.',
      'Gastou de novo? Você não sossega, né?',
    ],
    medium: [
      'Tá ficando mais pobre, hein, filho? 👀',
      'EITA, MÃO FURADA! Segura esse Pix!',
      'Você trabalha e o dinheiro faz turismo.',
      'O saldo pediu um minuto de silêncio.',
      'Puta que pariu, esse dinheiro não para na conta!',
    ],
    large: [
      'CARALHO! ESSA DOEU ATÉ EM MIM!',
      'Calma, herdeiro! Você não é o Banco Central!',
      'Rapaz... essa foi uma facada no saldo.',
      'Tá gastando ou financiando a economia brasileira?',
      'Esse gasto fez o saldo pedir socorro!',
    ],
  },
  funny: {
    small: ['Ih, lá foi um troquinho!', 'A carteira deu uma emagrecida.', 'E o dinheiro foi passear...'],
    medium: ['Opa, freia essa carteira! 😅', 'Esse Pix saiu correndo!', 'O saldo sentiu essa.'],
    large: ['EITA! Essa pesou na carteira!', 'O saldo tá precisando de férias.', 'A conta até ficou tonta!'],
  },
  discreet: {
    small: ['Nova saída detectada'],
    medium: ['Saída registrada'],
    large: ['Nova saída detectada'],
  },
};

const TRANSFER_PHRASES: Record<PushTone, string[]> = {
  sarcastic: ['Dinheiro mudou de endereço! 🔄', 'Transferiu? A grana só trocou de bolso.', 'O dinheiro passeou entre suas contas.'],
  funny: ['Dinheiro de mudança! 🔄', 'A grana só trocou de lugar.'],
  discreet: ['Transferência detectada'],
};

const PRIVATE_PHRASES: Record<PushTone, string[]> = {
  sarcastic: ['Ih, sua carteira se mexeu! 👀', 'O saldo tem novidades...', 'Tem movimentação nova na área!'],
  funny: ['Opa, tem novidade por aqui!', 'Sua carteira deu sinal de vida!'],
  discreet: ['Nova movimentação detectada'],
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
  const tag = 'pulso-evt-' + input.eventId;

  if (input.privacyMode) {
    const pool = PRIVATE_PHRASES[tone];
    const nextIdx = pickNextPhraseIndex(pool.length, input.lastPhraseIndex);
    return {
      nextPhraseIndex: nextIdx,
      payload: {
        title: pool[nextIdx],
        body: '',
        tag,
        url: targetUrl,
        eventId: input.eventId,
        tone,
        privacyMode: true,
      },
    };
  }

  const cents = Math.abs(Math.round(input.proposedAmountCents));
  const tier: ValueTier = input.proposedType === 'income'
    ? (cents < 5000 ? 'small' : cents < 15000 ? 'medium' : 'large')
    : (cents < 3000 ? 'small' : cents < 15000 ? 'medium' : 'large');
  const pool = input.proposedType === 'transfer'
    ? TRANSFER_PHRASES[tone]
    : input.proposedType === 'income'
      ? INCOME_PHRASES[tone][tier]
      : EXPENSE_PHRASES[tone][tier];
  const nextIdx = pickNextPhraseIndex(pool.length, input.lastPhraseIndex);
  const signedAmount = (input.proposedType === 'income' ? '+ ' : input.proposedType === 'expense' ? '− ' : '') +
    formatCentsBRLSimple(cents);

  return {
    nextPhraseIndex: nextIdx,
    payload: {
      title: pool[nextIdx],
      body: signedAmount,
      tag,
      url: targetUrl,
      eventId: input.eventId,
      tone,
      privacyMode: false,
    },
  };
}

export function buildTestPushPayload(tone: PushTone, privacyMode: boolean): PushMessagePayload {
  const safeTone: PushTone = isValidPushTone(tone) ? tone : 'sarcastic';
  const titleByTone: Record<PushTone, string> = {
    sarcastic: 'TÁ FUNCIONANDO, PORRA! 🔔',
    funny: 'Olha eu aqui! 🔔',
    discreet: 'Notificação de teste',
  };
  return {
    title: titleByTone[safeTone],
    body: '',
    tag: 'pulso-test-push',
    url: '/?from=push&sync=1',
    tone: safeTone,
    privacyMode,
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
