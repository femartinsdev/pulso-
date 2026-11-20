# PULSO 2.0 — Integração Cloudflare C6 + Web Push

## O que esta PR faz
Atualiza o **mesmo** Worker Cloudflare `pulso` e o banco D1 **já existente**, acrescentando Web Push criptografado. Não modifica Firestore, saldos, Atalhos, token C6 ou o app no Google AI Studio.

### Antes do MERGE (Cloudflare já vinculada à main)
1. Em Cloudflare → Storage & Databases → D1 → `pulso-c6-intake-db` → **Console**, execute **apenas** o SQL aditivo disponível em [migrations/002_web_push.sql](cloudflare-worker/migrations/002_web_push.sql). **Não execute o schema.sql inteiro no banco existente**.
2. Confirme as tabelas `push_subscriptions`, `push_preferences`, `push_deliveries` usando `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;`.
3. Tenha prontas as chaves VAPID válidas de um mesmo par ECDSA P-256. **Não compartilhe a chave privada em chats ou no GitHub.**
4. No Worker `pulso`, em **Settings → Variables & Secrets (runtime/Production)**, cadastre `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` como **Secrets**; `VAPID_SUBJECT` como `mailto:<seu email>` também protegido, sem pôr dados pessoais no GitHub. Confirme que `AUTHORIZED_OWNER_EMAIL` permanece configurado.
5. Revise o `wrangler.toml` no diff: Worker continua `pulso`, D1 binding `DB`, mesmo ID D1 e `ALLOWED_ORIGINS` incluindo `https://pulso-finan-as-ia.ai.studio`.
6. Confira CI GitHub verde e só então faça o merge. A Cloudflare terá uma nova build automática da `main`.

### Depois do MERGE
1. Cloudflare → Worker `pulso` → Deployments: confirmar sucesso e binding `DB`.
2. Abrir **PULSO publicado** no iPhone (não apenas Preview) → Configurações → Notificações → Ativar e dar permissão ao PWA instalado.
3. Fazer teste de Push do próprio PULSO. Depois conferir um próximo evento bancário real sem fazer Pix só para testar.
4. Verificar saldo/duplicatas, e revogar a inscrição no app se necessário.

### Segurança e observações
- `VAPID_PRIVATE_KEY` **nunca** deve aparecer em repositório, URL, captura de tela ou mensagem. A chave pública é publicada no endpoint autenticado `GET /api/v1/push/config`.
- O pacote original informado pelo Gemini foi preservado, com 2 correções de compatibilidade: domínio do PWA na lista CORS e versões de dependências já validadas no repositório.
- O Worker filtra OTP/promoções e deduplica antes de enviar notificações. Web Push no iPhone ainda precisa de teste real após publicação.
- Repositório público: não salvar dados de notificações, credenciais ou chaves privadas.
- Atenção: o PWA que está instalado pode precisar da **publicação da versão 2.0 no Google AI Studio**; somente atualizar o Worker não adiciona a interface de notificações ao app.
