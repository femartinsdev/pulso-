# PULSO — Cloudflare C6 intake

A pasta `cloudflare-worker/` contém o receptor de notificações C6 Bank (Workers + D1). A integração de frontend continua hospedada separadamente no Google AI Studio.

## Estado

- Código do Worker e testes integrados ao GitHub.
- Banco `pulso-c6-intake-db` identificado em `cloudflare-worker/wrangler.toml`.
- **Pendente**: criar as tabelas no D1, publicar o Worker e configurar o segredo `AUTHORIZED_OWNER_EMAIL` no painel Cloudflare. Ainda não foi testado o envio real do iPhone.
- **Não há deploy automático por GitHub Actions**; o workflow do GitHub apenas testa.

## 1. Preparar o banco (sem instalar nada)

1. Abra Cloudflare Dashboard → **Storage & Databases → D1** → **pulso-c6-intake-db**.
2. Abra a aba **Console**.
3. Copie e execute as instruções SQL de [cloudflare-worker/schema.sql](cloudflare-worker/schema.sql). Se o console recusar várias instruções, execute uma por vez, na ordem do arquivo.
4. Confirme as tabelas `device_tokens`, `intake_events` e `delivery_logs` com:
   `SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;`

Esse SQL apenas cria tabelas e índices se ainda não existirem; não altera o Firestore.

## 2. Publicar Worker a partir do GitHub (sem terminal local)

1. Cloudflare Dashboard → **Workers & Pages** → **Create application** → **Import a repository / Connect GitHub**.
2. Autorize o repositório `femartinsdev/pulso-` e selecione a branch `main`.
3. Configure o nome do Worker exatamente `pulso` e o **Root directory** como `cloudflare-worker`.
4. **Build command**: deixe vazio se opcional (o Worker TypeScript é compilado pelo Wrangler). **Deploy command**: `npx wrangler deploy`.
5. Confira que a configuração do Wrangler inclui o binding D1 `DB` com o banco `pulso-c6-intake-db`. Confirme que a conta está no plano Free.
6. Publique apenas depois de revisar as configurações. Cloudflare fornecerá uma URL `https://pulso.<seu-subdominio>.workers.dev`.

No primeiro deploy, se faltarem bindings/segredos, as rotas protegidas podem falhar. Não teste transações reais ainda.

## 3. Segredo e origem permitida

Após criar o Worker, vá a **Settings → Variables & Secrets**:

- Adicione `AUTHORIZED_OWNER_EMAIL` como **Secret** (nunca como variável pública ou no GitHub), com o mesmo e-mail verificado usado para entrar no Firebase do PULSO.
- A variável pública `FIREBASE_PROJECT_ID` já está definida no `wrangler.toml`.
- `ALLOWED_ORIGINS` deve conter a origem HTTPS exata do PULSO em que você realmente entrar. O arquivo tem origens de desenvolvimento e prévia, que podem precisar mudar depois que o PULSO for publicado.
- Confirme o binding `DB` ao banco correto em **Settings → Bindings**.

Não coloque tokens do iPhone em arquivos, em `wrangler.toml`, em URLs, em comentários ou em prints.

## 4. Teste com dados fictícios antes do iPhone real

No PULSO → Ajustes → Sincronização automática C6 Bank:
1. Configure a URL pública do Worker.
2. Teste a conexão usando sua sessão Google.
3. Gere a credencial individual do iPhone (o valor aparece uma vez).
4. Configure no Atalhos o POST HTTPS com cabeçalho `Authorization: Bearer` e corpo JSON com `bank`, `text` e `receivedAtIso` (veja o guia do PULSO).
5. Valide com notificação **fictícia**, depois com uma notificação real. Confirme não duplicar nem afetar saldo por Pix entre contas próprias.

Os limites dos planos gratuitos não são ilimitados. Nunca ative faturamento ou plano pago sem decidir conscientemente.

## Referências

- [Cloudflare Workers Builds](https://developers.cloudflare.com/workers/ci-cd/builds/)
- [Cloudflare Workers Builds — configuração](https://developers.cloudflare.com/workers/ci-cd/builds/configuration/)
- [Cloudflare D1](https://developers.cloudflare.com/d1/)
