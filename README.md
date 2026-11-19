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
- `GET /assinar?doc=<id>` — Widget de confirmação para `<iframe>`
- `GET /auth/login` e `GET /auth/callback` — Fluxo de login Microsoft Entra ID
- `POST /confirmar` — Registro da assinatura
- `GET /admin` — Painel gerencial (restrito a `ADMIN_EMAILS`)
- `GET /admin/export?format=xlsx|csv|xml` — Exportação de relatórios
- `GET /healthz` e `GET /livez` — Monitoramento de saúde do serviço

### Principais variáveis de ambiente (`.env`)
| Variável | Descrição | Padrão |
| :--- | :--- | :--- |
| `BASE_URL` | URL pública da aplicação | `http://localhost:8080` |
| `PORT` | Porta interna do servidor | `8080` |
| `DB_PATH` | Caminho do banco SQLite | `/app/data/signatures.db` |
| `AZURE_TENANT_ID` | Tenant ID do Microsoft Entra ID | `common` |
| `AZURE_CLIENT_ID` | Client ID da aplicação no Azure | — |
| `AZURE_CLIENT_SECRET` | Client Secret da aplicação no Azure | — |
| `ADMIN_EMAILS` | E-mails de administradores (separados por vírgula) | — |
| `SMTP_HOST` / `SMTP_PORT` | Servidor e porta SMTP | `smtp.office365.com` / `587` |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | Credenciais de envio SMTP | — |
| `SMTP_FROM_EMAIL` / `SMTP_REPLY_EMAIL` | Remetente e e-mail de resposta dos recibos | — |

Para rodar localmente com Go 1.22+ (`CGO_ENABLED=1`) ou executar os testes:
```bash
go run .
go test -v -race ./...
```

</details>

---

## 📄 Licença

Distribuído sob a licença **MIT**. Consulte [LICENSE](LICENSE) para mais detalhes.
