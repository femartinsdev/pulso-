# PULSO — Receptor Seguro C6 Bank (Cloudflare Workers + D1 Gratuitos)

Este Worker recebe notificações do **C6 Bank** enviadas em segundo plano pelo aplicativo **Atalhos do iOS**, valida autenticação por token revogável no cabeçalho HTTPS, bloqueia OTP/promoções, persiste na fila durável **Cloudflare D1** com idempotência e entrega ao PULSO autenticado com Firebase Auth JWT (sem ativar Blaze ou faturamento no Google Cloud).

## Limites da Camada Gratuita (referência)
- **Cloudflare Workers Free**: até 100.000 requisições/dia e 10 ms de CPU por requisição (sem cartão de crédito).
- **Cloudflare D1 Free**: até 5 milhões de leituras/dia, 100.000 escritas/dia e 5 GB de armazenamento.
- Este Worker aplica limpeza automática de eventos já confirmados (`acked_at`) com mais de 30 dias e mantém apenas os 200 registros de diagnóstico mais recentes.

## Passo a Passo de Publicação Gratuita

1. Crie uma conta gratuita em https://dash.cloudflare.com (não precisa cadastrar cartão).
2. No terminal, dentro da pasta `cloudflare-worker/`:
   ```bash
   npx wrangler login
   ```
3. Crie o banco D1 gratuito:
   ```bash
   npx wrangler d1 create pulso-c6-intake-db
   ```
4. Copie o `database_id` retornado no terminal e cole em `cloudflare-worker/wrangler.toml` substituindo `REPLACE_WITH_YOUR_D1_DATABASE_ID`.
5. (Opcional) Se você publicar o PULSO em um domínio próprio, adicione essa URL separada por vírgula em `ALLOWED_ORIGINS` dentro de `wrangler.toml`.
6. Aplique o esquema SQL no banco remoto:
   ```bash
   npx wrangler d1 execute pulso-c6-intake-db --remote --file=./schema.sql
   ```
7. Publique o Worker:
   ```bash
   npx wrangler deploy
   ```
8. Copie a URL publicada (ex.: `https://pulso-c6-intake.<seu-subdominio>.workers.dev`), cole em **PULSO → Configurações → Sincronização Automática C6 Bank** e clique em **Testar conexão**.
9. Ainda dentro do PULSO, gere o **Token individual do iPhone** (exibido uma única vez) e configure a ação **Obter Conteúdo de URL** no app Atalhos conforme o guia do aplicativo.

## Configuração privada (repositório público)

**Antes de usar as rotas autenticadas**: no painel Cloudflare, acesse o Worker -> Settings -> Variables and Secrets e crie um **Secret** com o nome `AUTHORIZED_OWNER_EMAIL` contendo o e-mail verificado usado para acessar o PULSO. Este valor não deve ser enviado ao GitHub nem compartilhado com terceiros. Verifique também se `FIREBASE_PROJECT_ID` e `ALLOWED_ORIGINS` estão corretos.

A versão publicada neste repositório não contém o e-mail pessoal configurado no projeto original.

**D1**: substitua `REPLACE_WITH_YOUR_D1_DATABASE_ID` por seu ID real e execute o SQL de `schema.sql` no console D1 (Execute SQL) antes de conectar o Worker. Você também pode usar Wrangler pelo CI, sem instalar Node.js no PC.

> A sincronização ainda não é considerada ativa até os testes do endpoint e do iPhone serem concluídos. Cotas gratuitas têm limites.
