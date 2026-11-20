# PULSO 2.0 — Receptor Seguro C6 Bank + Web Push (Cloudflare Workers + D1 Gratuitos)

Este Worker (`name = "pulso"`) recebe notificações do **C6 Bank** enviadas em segundo plano pelo aplicativo **Atalhos do iOS**, valida autenticação por token revogável no cabeçalho HTTPS, bloqueia OTP/promoções, persiste na fila durável **Cloudflare D1** (`pulso-c6-intake-db`, binding `DB`) com idempotência, envia notificações **Web Push criptografadas (RFC 8291 + RFC 8292)** para o iPhone e entrega eventos ao PULSO autenticado com Firebase Auth JWT.

## Limites da Camada Gratuita (referência)
- **Cloudflare Workers Free**: até 100.000 requisições/dia e 10 ms de CPU por requisição (sem cartão de crédito).
- **Cloudflare D1 Free**: até 5 milhões de leituras/dia, 100.000 escritas/dia e 5 GB de armazenamento.
- Este Worker aplica limpeza automática de eventos já confirmados (`acked_at`) com mais de 30 dias e mantém apenas os 200 registros de diagnóstico mais recentes.

## Variáveis e Segredos (Painel Cloudflare ou CLI)

Por segurança, **nenhum e-mail pessoal, token ou chave VAPID privada está fixado neste código**. Configure-os no painel da Cloudflare (**Workers & Pages → pulso → Settings → Variables and Secrets**) ou via `wrangler secret put`:

- `AUTHORIZED_OWNER_EMAIL` — e-mail da conta Google autorizada no PULSO (obrigatório)
- `VAPID_PUBLIC_KEY` — chave pública VAPID em Base64URL (para Web Push)
- `VAPID_PRIVATE_KEY` — chave privada VAPID em Base64URL (segredo criptografado)
- `VAPID_SUBJECT` — identificador VAPID (ex.: `mailto:seu-email@exemplo.com`)

## Atualização do Worker Existente para PULSO 2.0 (sem apagar o banco D1)

Como o banco D1 `pulso-c6-intake-db` já está vinculado no `wrangler.toml`, **não execute `d1 create` nem recrie tabelas existentes**. Dentro da pasta `cloudflare-worker/`:

1. Faça login na Cloudflare (se ainda não autenticou neste computador):
   ```bash
   npx wrangler login
   ```
2. Aplique apenas a **migration aditiva de Web Push** no banco D1 existente (preserva 100% dos tokens e eventos anteriores):
   ```bash
   npx wrangler d1 execute pulso-c6-intake-db --remote --file=./migrations/002_web_push.sql
   ```
3. Gere um par de chaves VAPID (ECDSA P-256) localmente:
   ```bash
   npx web-push generate-vapid-keys
   ```
4. Cadastre as variáveis/segredos criptografados no Worker `pulso`:
   ```bash
   npx wrangler secret put AUTHORIZED_OWNER_EMAIL
   npx wrangler secret put VAPID_SUBJECT
   npx wrangler secret put VAPID_PUBLIC_KEY
   npx wrangler secret put VAPID_PRIVATE_KEY
   ```
5. (Opcional) Se você usar um domínio próprio para o PULSO, acrescente-o separado por vírgula em `ALLOWED_ORIGINS` no `wrangler.toml`.
6. Publique a atualização sobre o Worker `pulso`:
   ```bash
   npx wrangler deploy
   ```
7. Abra o **PULSO instalado na Tela de Início do iPhone** (iOS 16.4+), acesse **Configurações → Notificações no iPhone**, toque em **Ativar notificações**, escolha o tom (**Sarcástico**, **Engraçado** ou **Discreto**) e toque em **Enviar notificação de teste**.

## Testes Locais do Worker

```bash
npm run typecheck
npm test
```
