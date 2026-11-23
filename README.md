# ZENITH-SIGNER

<div align="center">
  <img alt="Go" src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go&logoColor=white">
  <img alt="Docker" src="https://img.shields.io/badge/Docker-GHCR-2496ED?style=for-the-badge&logo=docker&logoColor=white">
  <img alt="License: MIT" src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge">
</div>

<br>

**Confirmação de leitura e assinatura eletrônica corporativa, simples para o colaborador e auditável para a empresa.**

O **Zenith Signer** transforma qualquer documento da sua intranet, wiki corporativa (como o **Outline**) ou portal interno em um termo formal com **aceite registrado**, utilizando a conta **Microsoft 365** que o colaborador já usa no dia a dia.

---

## 🎯 Por que usar o Zenith Signer?

Empresas precisam garantir que políticas internas, normas de segurança, comunicados de RH e procedimentos operacionais foram realmente lidos e aceitos pelos colaboradores — sem depender de planilhas manuais ou ferramentas caras de assinatura.

- **Zero atrito para o colaborador:** Login automático com a conta corporativa **Microsoft Entra ID** (sem novas senhas).
- **Rastreabilidade completa:** Captura automática de nome, e-mail, departamento, cargo, localização, data/hora, IP e geração de um **código verificador único (SHA-256)**.
- **Recibo imediato por e-mail:** Assim que confirma a leitura, o colaborador recebe um comprovante oficial direto na caixa de entrada via **Office 365**.
- **Sem assinaturas duplicadas:** O sistema identifica se o usuário já assinou o documento e exibe o comprovante já registrado.
- **Pronto para auditoria:** Painel administrativo (`/admin`) com filtros instantâneos e exportação em **Excel (XLSX)**, **CSV** e **XML**.
- **Leve e autônomo:** Roda em um único container Docker com banco embarcado de alta confiabilidade, pronto para operar 24/7.

---

## 💡 Como funciona na prática

1. **Publique o documento:** Incorpore o widget do Zenith Signer ao final de qualquer página da sua wiki ou intranet.
2. **O colaborador confirma a leitura:** Com um clique, ele se autentica via Microsoft 365 e registra o aceite.
3. **Comprovante e auditoria automáticos:** O sistema grava a assinatura, envia o recibo por e-mail e disponibiliza o registro no painel gerencial.

---

## 🧩 Incorporação em 1 minuto

Adicione o bloco abaixo na página do documento (substituindo o identificador em `doc=`):

```html
<iframe
  src="https://seu-dominio.com.br/assinar?doc=POLITICA-SEGURANCA-2026"
  width="100%"
  height="260"
  frameborder="0"
  style="border: none; border-radius: 8px;">
</iframe>
```

---

## 📊 Painel Administrativo e Exportação

Gestores autorizados acessam `/admin` para acompanhar em tempo real quem já leu e assinou cada documento, podendo filtrar por:

- **Documento**
- **Colaborador / E-mail**
- **Departamento e Cargo**
- **Código Hash ou Endereço IP**

Com um clique, é possível exportar o relatório filtrado para **Excel (`.xlsx`)**, **CSV** ou **XML**.

---

## 🚀 Implantação Rápida (Docker)

1. Copie o modelo de configuração e preencha suas credenciais do Microsoft Entra ID e SMTP:
   ```bash
   cp .env.example .env
   ```

2. Suba o serviço com Docker Compose (disponível na porta `8087`):
   ```bash
   docker compose pull
   docker compose up -d
   ```

> **Dica:** No App Registration do Microsoft Entra ID, cadastre `<BASE_URL>/auth/callback` como URI de redirecionamento.

<details>
<summary>⚙️ Referência de configuração e endpoints (clique para expandir)</summary>

### Endpoints disponíveis
- `GET /` — Portal inicial com validador público de assinatura por Hash (`?hash=...`)
- `GET /assinar?doc=<id>` — Widget de confirmação para `<iframe>`
- `GET /auth/login` e `GET /auth/callback` — Fluxo de login Microsoft Entra ID
- `POST /confirmar` — Registro da assinatura
- `GET /admin` — Painel gerencial (restrito a `ADMIN_EMAILS`)
- `GET /admin/export?format=xlsx|csv|xml` — Exportação de relatórios
- `GET /admin/documentos` — Cadastro de documentos do Outline, versões, decisões e verificação de integridade
- `POST /webhooks/outline` — Recebe alterações do Outline (assinado com `OUTLINE_WEBHOOK_SECRET`)
- `GET /healthz` e `GET /livez` — Monitoramento de saúde do serviço

### Principais variáveis de ambiente (`.env`)
| Variável | Descrição | Padrão |
| :--- | :--- | :--- |
| `APP_NAME` | Nome exibido no título e cabeçalho do painel admin | `Zenith Signer` |
| `BASE_URL` | URL pública da aplicação | `http://localhost:8080` |
| `PORT` | Porta interna do servidor | `8080` |
| `DB_PATH` | Caminho do banco SQLite | `/app/data/signatures.db` |
| `AZURE_TENANT_ID` | Tenant ID do Microsoft Entra ID | `common` |
| `AZURE_CLIENT_ID` | Client ID da aplicação no Azure | — |
| `AZURE_CLIENT_SECRET` | Client Secret da aplicação no Azure | — |
| `ADMIN_EMAILS` | E-mails de administradores (separados por vírgula) | — |
| `SESSION_SECRET` | Chave secreta HMAC para assinatura dos cookies de sessão e dos tokens anti-CSRF | *(aleatória)* |
| `ALLOWED_EMBED_ORIGINS` | Origens (`https://host[:porta]`, aceita `https://*.dominio`) autorizadas a incorporar `/assinar` em iframe | *(só a própria aplicação)* |
| `TRUSTED_PROXIES` | IPs/CIDRs de proxies reversos cujos `X-Forwarded-For`/`X-Real-IP` são aceitos | *(nenhum — usa o IP da conexão)* |
| `BACKUP_ENABLED` | Liga/desliga o backup automático do banco | `true` |
| `BACKUP_DIR` | Pasta onde os backups são gravados | `<pasta do DB_PATH>/backups` |
| `BACKUP_INTERVAL` | Intervalo entre backups (`6h`, `24h`...) | `24h` |
| `BACKUP_RETENTION` | Quantidade de backups mantidos (os mais antigos são apagados) | `7` |
| `AUDIT_SECRET` | Chave do selo HMAC da cadeia de auditoria. **Defina uma vez e nunca altere** | *(derivada do `SESSION_SECRET`)* |
| `OUTLINE_URL` | URL do Outline (ex.: `https://wiki.empresa.com.br`) | *(desativado)* |
| `OUTLINE_API_KEY` | Chave de API do Outline (Settings → API & Apps) | — |
| `OUTLINE_WEBHOOK_SECRET` | Segredo do webhook do Outline (`ol_whs_...`) | *(sem webhook)* |
| `OUTLINE_SYNC_INTERVAL` | Intervalo da sincronização periódica com o Outline | `15m` |
| `SMTP_HOST` / `SMTP_PORT` | Servidor e porta SMTP | `smtp.office365.com` / `587` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Credenciais de envio SMTP | — |
| `SMTP_FROM_EMAIL` / `SMTP_REPLY_EMAIL` | Remetente e e-mail de resposta dos recibos | — |
| `EMAIL_LOGO_URL` | URL pública da logo exibida no cabeçalho do e-mail | *(vazio)* |
| `EMAIL_ACCENT_COLOR` | Cor hex das barras superior/inferior do e-mail | `#8BC74B` |
| `EMAIL_SIGNATURE_NAME` | Nome exibido na assinatura do e-mail | `Zenith Signer` |
| `LOG_LEVEL` | Nível mínimo dos logs (`DEBUG`, `INFO`, `WARN`, `ERROR`) | `INFO` |
| `LOG_FORMAT` | Formato dos logs (`text` ou `json`) | `text` |
| `LOG_FILE` | Caminho opcional para salvar logs em arquivo além do `stdout` | *(vazio)* |

### Integração com o Outline
Em `/admin/documentos` o administrador busca um documento do Outline pelo título (ou cola a URL) e o cadastra. O Zenith Signer então:

1. **Captura a versão 1** do texto e guarda o SHA-256 do conteúdo (a linha do próprio widget é ignorada no cálculo).
2. **Insere o widget no topo da página** via API do Outline e confirma se ele foi exibido como embed. Se o Outline o exibir como link, ou se a inserção falhar, o painel mostra o link pronto para colar com `/embed`.
3. **Acompanha alterações**: pelo webhook (`<BASE_URL>/webhooks/outline`, assinado com `OUTLINE_WEBHOOK_SECRET`) e por uma sincronização periódica. Cada mudança de texto vira uma nova versão **aguardando decisão**, com a comparação linha a linha.
4. **O admin decide**: *exigir nova assinatura* (todos voltam a ver o pedido de confirmação, com aviso de atualização) ou *correção menor* (as assinaturas continuam válidas).

Cada assinatura fica vinculada à versão exata lida (ID da versão e hash do conteúdo). Se a página mudar enquanto o widget estiver aberto, a confirmação é recusada e o colaborador vê a versão nova. Para vincular um documento que já tinha um embed antigo, informe o identificador usado no `doc=` e marque *Manter assinaturas anteriores*.

**Configuração no Outline:** crie uma chave de API (Settings → API & Apps) com uma conta que tenha permissão de edição nos documentos e, opcionalmente, um webhook (Settings → Webhooks) para `<BASE_URL>/webhooks/outline` com os eventos de documentos.

### Cadeia de auditoria
Cada nova assinatura recebe um número de sequência, o hash da assinatura anterior e um selo HMAC-SHA256 (chave `AUDIT_SECRET`) sobre todos os campos. Em `/admin/documentos` → *Verificar integridade agora*, o sistema recalcula a cadeia e aponta qualquer registro alterado, inserido ou removido diretamente no banco. Assinaturas anteriores a esta funcionalidade continuam válidas, mas ficam fora da cadeia.

### Backup
O serviço gera automaticamente uma cópia consistente do banco com `VACUUM INTO` (seguro com a aplicação em uso), verifica a integridade da cópia (`PRAGMA quick_check`) e mantém apenas os `BACKUP_RETENTION` arquivos mais recentes (`signatures-AAAAMMDD-HHMMSS.mmm.db`). No Docker, eles ficam em `./data/backups` no host.

> Os backups ficam no mesmo disco do banco. Para proteção contra perda do servidor, copie periodicamente `./data/backups` para outro local (NAS, OneDrive, outro servidor).

Para restaurar: pare o container, substitua `./data/signatures.db` pelo arquivo de backup desejado (removendo `signatures.db-wal` e `signatures.db-shm`, se existirem) e suba novamente.

### Segurança
- **Anti-CSRF:** o `POST /confirmar` exige um token HMAC vinculado à sessão (campo `csrf_token`, gerado no widget) e rejeita requisições com cabeçalho `Origin` diferente de `BASE_URL`.
- **Anti-clickjacking:** com o colaborador logado (quando é possível assinar), `/assinar` só pode ser incorporado pelas origens de `ALLOWED_EMBED_ORIGINS` (`Content-Security-Policy: frame-ancestors`). Sem login, o widget mostra apenas o botão de entrar e aceita qualquer origem — necessário para a verificação do Outline ao criar um embed (`/urls.checkEmbed`). Todas as demais rotas, inclusive `/admin`, recusam ser exibidas em iframe.
- **IP auditável:** `X-Forwarded-For`/`X-Real-IP` só são considerados quando a conexão vem de um proxy listado em `TRUSTED_PROXIES`.
- **Uma assinatura por colaborador e documento:** garantida por índice único no banco (`document_name`, `user_email`), inclusive em cliques simultâneos. Ao atualizar uma base antiga que já tenha duplicatas, a migração mantém a primeira assinatura de cada colaborador e move as demais para a tabela `signatures_duplicates`; os hashes movidos continuam válidos no validador público.
- **Identificador do documento:** `doc` aceita até 200 caracteres (acentos, espaços e pontuação), recusando caracteres de controle e invisíveis; os cabeçalhos do e-mail são sanitizados e o assunto é codificado em RFC 2047.

Para rodar localmente com Go 1.22+ (`CGO_ENABLED=1`) ou executar os testes:
```bash
go run .
go test -v -race ./...
```

</details>

---

## 📄 Licença

Distribuído sob a licença **MIT**. Consulte [LICENSE](LICENSE) para mais detalhes.
