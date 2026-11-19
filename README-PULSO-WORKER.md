# PULSO — Cloudflare C6 intake

A pasta `cloudflare-worker/` contém o receptor HTTPS de notificações do C6 Bank (Cloudflare Workers + D1).

**Ainda não está publicado nem conectado ao PULSO.** O `wrangler.toml` contém um `database_id` placeholder. Para uso real, crie D1 gratuito na sua conta Cloudflare e substitua o placeholder. Configure `AUTHORIZED_OWNER_EMAIL` como **Secret** no painel Cloudflare; nunca salve o e-mail pessoal ou tokens em arquivos públicos.

## Testes

O workflow **Verificar Worker PULSO (sem deploy)** executa TypeScript e testes de segurança ao abrir a PR, sem acesso à Cloudflare e sem gravar dados financeiros.

## Publicação sem instalar programas no PC

Pelo painel Cloudflare: Workers → Create/Import Git repository → conecte o repositório → configure o diretório `cloudflare-worker`, vincule D1 ao binding `DB`, adicione o Secret `AUTHORIZED_OWNER_EMAIL` e aplique `cloudflare-worker/schema.sql` no banco **antes** do deploy. Confirme o nome do Worker e as origens permitidas em `wrangler.toml`.

**Não ative deploy automático nem envie notificações reais até configurar D1, o Secret e verificar o endpoint.** A configuração inicial requer substituir `REPLACE_WITH_YOUR_D1_DATABASE_ID` por um ID real.

Esta PR contém apenas o Worker e testes; a implementação do PULSO no Google AI Studio não é incluída aqui.
