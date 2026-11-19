/**
 * Parser determinístico exclusivo para notificações do C6 Bank no Cloudflare Worker.
 *
 * Regras auditadas:
 * 1. Aceita APENAS C6 Bank no endpoint automático (rejeita outros bancos sem gravar).
 * 2. Bloqueia OTP, códigos de segurança/2FA e promoções ANTES de qualquer persistência
 *    (jamais grava o texto de OTP sequer em logs de diagnóstico).
 * 3. Classifica alta confiança exclusivamente para compra no débito, Pix enviado e
 *    Pix recebido de terceiros.
 * 4. Encaminha para revisão (confidence: 'ambiguous') compras no cartão de crédito,
 *    possíveis transferências entre contas próprias e textos com direção incerta.
 * 5. Gera chave de idempotência precisa (minuto + valor + hash do texto normalizado ou eventId)
 *    para bloquear reenvios idênticos SEM descartar duas compras legítimas do mesmo valor.
 */

export type WorkerTransactionType = 'income' | 'expense' | 'transfer';

export type WorkerAmbiguityReason =
  | 'credit_card_purchase'
  | 'possible_own_transfer'
  | 'unclear_direction'
  | 'missing_merchant';

export type WorkerIgnoredCode =
  | 'ignored_otp'
  | 'ignored_promo'
  | 'ignored_bank'
  | 'ignored_insufficient_data'
  | 'invalid_payload';

export interface IntakeRequestPayload {
  bank?: string;
  bankOrigin?: string;
  title?: string;
  text?: string;
  body?: string;
  message?: string;
  rawNotificationText?: string;
  receivedAt?: string;
  receivedAtIso?: string;
  occurredAt?: string;
  eventId?: string;
  notificationId?: string;
  amountCents?: number;
}

export interface ParsedC6Event {
  bankOrigin: 'c6_bank';
  rawSummary: string;
  merchantName: string | null;
  proposedDescription: string;
  proposedAmountCents: number;
  proposedType: WorkerTransactionType;
  confidence: 'high' | 'ambiguous';
  ambiguityReason: WorkerAmbiguityReason | null;
  occurredAt: string;
  idempotencyKey: string;
}

export interface C6EvaluationResult {
  accepted: boolean;
  event?: ParsedC6Event;
  ignoredCode?: WorkerIgnoredCode;
  reasonMessage: string;
  /** Resumo seguro para diagnóstico (nunca contém texto de OTP). */
  safeDiagnosticSummary?: string;
}

const MAX_AMOUNT_CENTS = 100_000_000_000;

const SECURITY_CODE_PATTERNS: RegExp[] = [
  /c[oó]digo\s+(?:de\s+)?(?:verifica[cç][aã]o|seguran[cç]a|acesso|confirma[cç][aã]o|autentica[cç][aã]o|uso\s+[uú]nico|tempor[aá]rio)/i,
  /use\s+o\s+c[oó]digo/i,
  /seu\s+c[oó]digo\s+(?:[eé]|:)/i,
  /n[aã]o\s+compartilhe\s+(?:este|esse|o)\s+(?:c[oó]digo|token|pin)/i,
  /\b(?:otp|2fa|token\s+de\s+seguran[cç]a|c[oó]digo\s+token|c[oó]digo\s+sms)\b/i,
  /chave\s+de\s+seguran[cç]a|senha\s+tempor[aá]ria|valida[cç][aã]o\s+de\s+dispositivo|pin\s+de\s+seguran[cç]a/i,
  /autorize\s+o\s+acesso|confirme\s+seu\s+login|tentativa\s+de\s+login/i,
  /\bc[oó]digo\b[^0-9]{0,20}\b\d{4,8}\b/i,
];

const HARD_TRANSACTION_VERBS: RegExp[] = [
  /compra\s+(?:aprovada|realizada|no\s+(?:cr[eé]dito|d[eé]bito)|efetuada)/i,
  /pix\s+(?:recebido|enviado|realizado|efetuado|agendado\s+efetivado)/i,
  /voc[eê]\s+(?:recebeu|enviou|pagou|fez\s+um\s+pix|transferiu)/i,
  /transfer[eê]ncia\s+(?:recebida|enviada|realizada|efetuada)/i,
  /pagamento\s+(?:realizado|efetuado|aprovado|de\s+boleto\s+realizado)/i,
  /boleto\s+pago/i,
  /cr[eé]dito\s+em\s+conta|d[eé]bito\s+em\s+conta|dep[oó]sito\s+(?:recebido|realizado|confirmado)/i,
  /saque\s+(?:realizado|efetuado|aprovado)/i,
  /estorno\s+(?:recebido|realizado|creditado)/i,
];

const PROMOTIONAL_PATTERNS: RegExp[] = [
  /\b(?:promo[cç][aã]o|promocional|oferta\s+especial|aproveite|black\s+friday|sorteio|cupom|cupons)\b/i,
  /\b(?:cashback|pontos?\s+[aá]tomos|ganhe\s+r\$|indique\s+e\s+ganhe|convide\s+amigos)\b/i,
  /\b(?:limite\s+pr[eé]-?aprovado|empr[eé]stimo|cr[eé]dito\s+pessoal|cart[aã]o\s+aprovado|aumente\s+seu\s+limite)\b/i,
  /\b(?:parcelamento\s+dispon[ií]vel|parcele\s+sua\s+fatura|invista\s+no\s+cdb|rende\s+\d+%)\b/i,
  /\b(?:confira\s+no\s+app|novidade\s+no\s+app|baixe\s+agora|clique\s+e\s+aproveite|exclusivo\s+para\s+voc[eê])\b/i,
  /\b(?:sua\s+fatura\s+(?:fechou|vence)|lembrete\s+de\s+vencimento|seu\s+limite\s+(?:atual|dispon[ií]vel)\s+[eé])\b/i,
];

const MOVEMENT_CUES: RegExp[] = [
  ...HARD_TRANSACTION_VERBS,
  /\b(?:pix|compra|pagamento|boleto|transfer[eê]ncia|dep[oó]sito|saque|estorno|d[eé]bito|recebido|recebeu|enviado|enviou|pagou)\b/i,
];

const OWN_TRANSFER_PATTERNS: RegExp[] = [
  /entre\s+contas/i,
  /mesma\s+titularidade/i,
  /transfer[eê]ncia\s+pr[oó]pria/i,
  /para\s+sua\s+conta/i,
  /de\s+sua\s+conta/i,
  /caixa\s*tem|caixatem/i,
];

const CREDIT_CARD_PATTERNS: RegExp[] = [
  /no\s+cr[eé]dito/i,
  /fun[cç][aã]o\s+cr[eé]dito/i,
  /cart[aã]o\s+de\s+cr[eé]dito/i,
  /compra\s+cr[eé]dito/i,
  /parcelad[oa]\s+em\s+\d+x/i,
];

export function sanitizeText(raw: string): string {
  return raw
    .replace(/<[^>]*>/g, ' ')
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
    .replace(/\b(?:\d[ -]?){13,19}\b/g, '[número mascarado]')
    .replace(/\s+/g, ' ')
    .trim();
}

function parseBRLToCents(raw: string): number | null {
  const cleaned = raw.trim().replace(/[^\d.,]/g, '');
  if (!cleaned) return null;

  let normalized = cleaned;
  const lastComma = cleaned.lastIndexOf(',');
  const lastDot = cleaned.lastIndexOf('.');

  if (lastComma > lastDot) {
    normalized = cleaned.replace(/\./g, '').replace(',', '.');
  } else if (lastDot > lastComma) {
    const afterDot = cleaned.slice(lastDot + 1);
    if (afterDot.length === 3 && !cleaned.includes(',')) {
      normalized = cleaned.replace(/\./g, '');
    } else {
      normalized = cleaned.replace(/,/g, '');
    }
  }

  const parsed = Number.parseFloat(normalized);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  const cents = Math.round(parsed * 100);
  if (cents <= 0 || cents > MAX_AMOUNT_CENTS) return null;
  return cents;
}

function extractAmountCents(text: string, hint?: number): number | null {
  if (typeof hint === 'number' && Number.isInteger(hint) && hint > 0 && hint <= MAX_AMOUNT_CENTS) {
    return hint;
  }

  const explicitBrl = text.match(
    /R\$\s?(\d{1,3}(?:\.\d{3})*,\d{2}|\d+[.,]\d{2}|\d{1,3}(?:\.\d{3})+|\d+)(?!\d)/i
  );
  if (explicitBrl?.[1]) {
    const rawNum = explicitBrl[1];
    if (rawNum.includes(',') || rawNum.includes('.')) {
      const cents = parseBRLToCents(rawNum);
      if (cents) return cents;
    } else {
      const whole = Number.parseInt(rawNum, 10);
      if (Number.isFinite(whole) && whole > 0 && whole * 100 <= MAX_AMOUNT_CENTS) {
        return whole * 100;
      }
    }
  }

  const contextualBrl = text.match(/valor\s+(?:de\s+)?(\d{1,3}(?:\.\d{3})*,\d{2}|\d+,\d{2})/i);
  if (contextualBrl?.[1]) {
    return parseBRLToCents(contextualBrl[1]);
  }

  return null;
}

function normalizeIsoTimestamp(value?: string, fallbackIso?: string): string {
  const candidate = (value ?? '').trim();
  if (candidate.length >= 10) {
    const parsed = new Date(candidate);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString();
    }
    if (/^\d{4}-\d{2}-\d{2}$/.test(candidate)) {
      return `${candidate}T12:00:00.000Z`;
    }
    const brDateMatch = candidate.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2}))?/);
    if (brDateMatch) {
      const [, dd, mm, yyyy, hh = '12', min = '00'] = brDateMatch;
      return `${yyyy}-${mm}-${dd}T${hh}:${min}:00-03:00`;
    }
  }
  return fallbackIso ?? new Date().toISOString();
}

function isC6BankNotification(payload: IntakeRequestPayload, sanitizedText: string): boolean {
  const explicitBank = (payload.bankOrigin ?? payload.bank ?? '').trim().toLowerCase();
  if (explicitBank) {
    if (/^(?:c6|c6_bank|c6bank|c6\s+bank)$/.test(explicitBank)) {
      return true;
    }
    // Se outro banco foi informado explicitamente, rejeita imediatamente.
    return false;
  }

  const combined = `${payload.title ?? ''} ${sanitizedText}`.toLowerCase();
  return /\bc6\s*bank\b|\bc6bank\b|\bc6\b/.test(combined);
}

function extractMerchant(text: string, type: WorkerTransactionType): string | null {
  const cleaned = text.replace(/^(?:c6\s*bank|c6bank|c6)\s*[:\-–·]\s*/i, '').trim();

  const patterns: RegExp[] = [
    /(?:no\s+estabelecimento|estabelecimento)\s+([A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9\s.&'/-]{1,56})/i,
    /R\$\s?[\d.,]+\s*(?:em|na|no|para|de|-|–)\s+([A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9\s.&'/-]{1,56})/i,
    /(?:para|destinat[aá]rio)\s+([A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9\s.&'/-]{1,56})/i,
    /(?:pix\s+recebido\s+de|recebeu\s+(?:um\s+pix|transfer[eê]ncia)?\s*(?:no\s+valor\s+de\s+R\$\s?[\d.,]+\s+)?de)\s+([A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9\s.&'/-]{1,56})/i,
    /\bem\s+([A-Za-zÀ-ÿ0-9][A-Za-zÀ-ÿ0-9\s.&'/-]{1,56})/i,
  ];

  for (const rx of patterns) {
    const match = cleaned.match(rx);
    if (match?.[1]) {
      const candidate = match[1]
        .replace(
          /\b(?:no\s+valor\s+de|em\s+\d{2}\/\d{2}|[àa]s\s+\d{2}[:h]\d{2}|com\s+cart[aã]o|final\s+\d{4}|no\s+d[eé]bito|no\s+cr[eé]dito).*$/i,
          ''
        )
        .replace(/[.,;:\-–]+$/g, '')
        .trim();

      if (
        candidate.length >= 2 &&
        !/\bR\$\b|R$/i.test(candidate) &&
        !/^(?:conta|cart[aã]o|cr[eé]dito|d[eé]bito|valor|reais|pix|sua\s+conta|d[eé]bito\s+de|cr[eé]dito\s+de)/i.test(
          candidate
        )
      ) {
        return candidate.slice(0, 80);
      }
    }
  }

  if (type === 'income' && /pix/i.test(cleaned)) return 'Pix recebido';
  if (type === 'expense' && /pix/i.test(cleaned)) return 'Pix enviado';
  if (type === 'expense' && /boleto/i.test(cleaned)) return 'Pagamento de boleto';
  if (type === 'expense' && /saque/i.test(cleaned)) return 'Saque';
  if (type === 'transfer') return 'Transferência entre contas';

  return null;
}

function fnv1aHex64(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let i = 0; i < input.length; i += 1) {
    const c = input.charCodeAt(i);
    h1 ^= c;
    h1 = Math.imul(h1, 0x01000193);
    h2 ^= c + i;
    h2 = Math.imul(h2, 0x85ebca6b);
  }
  return `${(h1 >>> 0).toString(16).padStart(8, '0')}${(h2 >>> 0).toString(16).padStart(8, '0')}`;
}

export function buildC6IdempotencyKey(params: {
  amountCents: number;
  occurredAtIso: string;
  sanitizedText: string;
  explicitEventId?: string;
}): string {
  const explicit = (params.explicitEventId ?? '').trim();
  if (explicit.length >= 4) {
    const cleanId = explicit.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
    if (cleanId.length >= 4) {
      return `c6-evt-${cleanId}`.slice(0, 128);
    }
  }

  // Bucket por minuto + valor + hash do texto normalizado:
  // Reenvios idênticos da mesma notificação caem na mesma chave;
  // duas compras legítimas do mesmo valor em horários distintos geram chaves diferentes.
  const minuteBucket = params.occurredAtIso.slice(0, 16).replace(/[^0-9]/g, '');
  const textFingerprint = fnv1aHex64(
    params.sanitizedText
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  );

  return `c6-${minuteBucket}-${params.amountCents}-${textFingerprint}`.slice(0, 128);
}

export function evaluateC6Notification(
  payload: IntakeRequestPayload,
  nowIso: string = new Date().toISOString()
): C6EvaluationResult {
  const rawBody =
    payload.rawNotificationText ??
    payload.text ??
    payload.body ??
    payload.message ??
    '';

  const combinedRaw = [payload.title, rawBody]
    .filter((part): part is string => typeof part === 'string' && part.trim().length > 0)
    .join(' · ');

  const sanitized = sanitizeText(combinedRaw);
  if (sanitized.length < 4) {
    return {
      accepted: false,
      ignoredCode: 'invalid_payload',
      reasonMessage: 'Payload sem texto de notificação suficiente.',
      safeDiagnosticSummary: 'Texto vazio ou muito curto',
    };
  }

  // 1. Bloqueio prioritário de OTP / códigos de segurança (NUNCA armazenar texto!)
  for (const pattern of SECURITY_CODE_PATTERNS) {
    if (pattern.test(sanitized)) {
      return {
        accepted: false,
        ignoredCode: 'ignored_otp',
        reasonMessage: 'Mensagem com código de segurança/OTP bloqueada por privacidade.',
        safeDiagnosticSummary: 'Código de segurança/OTP bloqueado (conteúdo descartado)',
      };
    }
  }

  // 2. Restrição estrita: apenas C6 Bank no endpoint automático
  if (!isC6BankNotification(payload, sanitized)) {
    return {
      accepted: false,
      ignoredCode: 'ignored_bank',
      reasonMessage: 'Notificação ignorada: endpoint automático aceita apenas C6 Bank.',
      safeDiagnosticSummary: 'Origem diferente de C6 Bank',
    };
  }

  // 3. Bloqueio de promoções e avisos informativos sem transação real
  const hasHardVerb = HARD_TRANSACTION_VERBS.some((rx) => rx.test(sanitized));
  if (!hasHardVerb) {
    for (const pattern of PROMOTIONAL_PATTERNS) {
      if (pattern.test(sanitized)) {
        return {
          accepted: false,
          ignoredCode: 'ignored_promo',
          reasonMessage: 'Notificação promocional ou informativa do C6 Bank ignorada.',
          safeDiagnosticSummary: 'Aviso promocional/informativo ignorado',
        };
      }
    }
  }

  // 4. Extração de valor em centavos inteiros
  const amountCents = extractAmountCents(sanitized, payload.amountCents);
  if (!amountCents) {
    return {
      accepted: false,
      ignoredCode: 'ignored_insufficient_data',
      reasonMessage: 'Nenhum valor monetário em reais (R$) identificado.',
      safeDiagnosticSummary: 'Sem valor em R$ identificado',
    };
  }

  if (!MOVEMENT_CUES.some((rx) => rx.test(sanitized))) {
    return {
      accepted: false,
      ignoredCode: 'ignored_insufficient_data',
      reasonMessage: 'Texto contém valor, mas sem indício de movimentação financeira real.',
      safeDiagnosticSummary: 'Sem verbo/indício de movimentação',
    };
  }

  const lower = sanitized.toLowerCase();
  const isCreditCard = CREDIT_CARD_PATTERNS.some((rx) => rx.test(sanitized));
  const isPossibleOwnTransfer = OWN_TRANSFER_PATTERNS.some((rx) => rx.test(sanitized));

  let proposedType: WorkerTransactionType = 'expense';
  let confidence: 'high' | 'ambiguous' = 'high';
  let ambiguityReason: WorkerAmbiguityReason | null = null;

  if (isPossibleOwnTransfer) {
    proposedType = 'transfer';
    confidence = 'ambiguous';
    ambiguityReason = 'possible_own_transfer';
  } else if (isCreditCard) {
    proposedType = 'expense';
    confidence = 'ambiguous';
    ambiguityReason = 'credit_card_purchase';
  } else if (
    /pix\s+recebido|voc[eê]\s+recebeu|recebeu\s+(?:um\s+)?pix|transfer[eê]ncia\s+recebida|dep[oó]sito\s+(?:recebido|confirmado)|cr[eé]dito\s+em\s+conta|estorno\s+(?:recebido|creditado)/.test(
      lower
    )
  ) {
    proposedType = 'income';
    confidence = 'high';
  } else if (
    /compra\s+(?:aprovada|realizada|efetuada)|no\s+d[eé]bito|d[eé]bito\s+em\s+conta|pix\s+(?:enviado|realizado|efetuado)|voc[eê]\s+(?:enviou|pagou|fez\s+um\s+pix|transferiu)|pagamento\s+(?:realizado|efetuado|aprovado)|boleto\s+pago|saque\s+(?:realizado|efetuado|aprovado)/.test(
      lower
    )
  ) {
    proposedType = 'expense';
    confidence = 'high';
  } else {
    proposedType = 'expense';
    confidence = 'ambiguous';
    ambiguityReason = 'unclear_direction';
  }

  const merchantName = extractMerchant(sanitized, proposedType);
  if (!merchantName && confidence === 'high') {
    confidence = 'ambiguous';
    ambiguityReason = 'missing_merchant';
  }

  const occurredAt = normalizeIsoTimestamp(
    payload.receivedAtIso ?? payload.receivedAt ?? payload.occurredAt,
    nowIso
  );

  const proposedDescription = (
    merchantName ? `C6 Bank · ${merchantName}` : 'C6 Bank · Movimentação via notificação'
  ).slice(0, 160);

  const idempotencyKey = buildC6IdempotencyKey({
    amountCents,
    occurredAtIso: occurredAt,
    sanitizedText: sanitized,
    explicitEventId: payload.eventId ?? payload.notificationId,
  });

  return {
    accepted: true,
    reasonMessage:
      confidence === 'high'
        ? 'Movimentação C6 Bank identificada com alta confiança.'
        : 'Movimentação C6 Bank enfileirada para revisão (ambiguidade detectada).',
    safeDiagnosticSummary: `${proposedDescription} (${confidence})`.slice(0, 120),
    event: {
      bankOrigin: 'c6_bank',
      rawSummary: sanitized.slice(0, 320),
      merchantName,
      proposedDescription,
      proposedAmountCents: amountCents,
      proposedType,
      confidence,
      ambiguityReason,
      occurredAt,
      idempotencyKey,
    },
  };
}
