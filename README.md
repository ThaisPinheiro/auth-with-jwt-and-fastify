# Auth with JWT (Fastify + TypeScript + MongoDB)

Este projeto é uma API completa de autenticação e autorização utilizando **JWT (JSON Web Token)**, desenvolvida com [Fastify](https://www.fastify.io/), [TypeScript](https://www.typescriptlang.org/) e [MongoDB](https://www.mongodb.com/).

## Stack e arquitetura

- **Fastify** — Framework de alto desempenho para Node.js, com foco em extensibilidade via plugins e decorators.
- **Zod** — Validação de esquemas e parsing de dados para garantir entradas seguras.
- **TypeScript** — Tipagem forte para garantir consistência e previsibilidade.
- **MongoDB** — Armazenamento dos usuários e tokens invalidados (blacklist).
- **JWT (JSON Web Token)** — Implementação de autenticação stateless segura, com suporte a blacklist e roles.
- **Docker** — Utilizado para rodar o MongoDB.

## Estrutura em camadas

- **src/** — Estrutura principal do projeto
  - **routes/** — Definição dos endpoints e aplicação de middlewares
  - **controllers/** — Camada HTTP: validação das requisições e formatação de respostas
  - **services/** — Lógica de negócio (autenticação, registro, logout, roles)
  - **plugins/** — Plugins/middlewares Fastify reutilizáveis (verifyJWT, authorizeRole)
  - **model/** — Esquemas e persistência (User, TokenBlacklist)
  - **helpers/** — Utilitários e funções auxiliares
  - **env/** — Configuração de variáveis de ambiente

Essa organização permite testar e evoluir cada camada isoladamente, mantendo o princípio da Single Responsibility.

## Principais conceitos aplicados
### 1. Autenticação Stateless

Após o login bem-sucedido, o servidor gera um JWT assinado com o segredo (`JWT_SECRET`).
Esse token contém um payload com as informações essenciais do usuário (ex: sub,  role) e é enviado ao cliente, que o inclui no cabeçalho `Authorization: Bearer <token>` em cada requisição protegida.

Nenhuma sessão é mantida no servidor — a validação é feita apenas pela assinatura e integridade do token.

### 2. Assinatura e Verificação

O token é assinado com HMAC SHA-256, usando a variável de ambiente `JWT_SECRET`.

A verificação ocorre em cada rota protegida via `verifyJWT`, garantindo:
- Autenticidade (foi assinado pelo servidor legítimo)
- Integridade (não foi modificado)
- Expiração controlada (`exp` claim)

### 3. Blacklist (Logout seguro)

Mesmo sendo stateless, o projeto implementa logout real via Capped Collection no MongoDB.
Cada token inválido (logout) é armazenado temporariamente na coleção `TokenBlacklist`, e verificado antes de aceitar uma requisição.

Esse padrão é essencial para revogação de tokens em sistemas sensíveis, evitando acesso indevido após logout.

### 4. Autorização baseada em roles

Após a autenticação, o payload do token contém o papel (`role`) do usuário.
Um decorator `authorizeRole(role)` é usado para garantir que apenas usuários com permissão adequada possam acessar determinadas rotas.

```typescript
  app.get('/admin', {
    preHandler: [app.verifyJWT, app.authorizeRole('admin')]
  }, async () => ({ message: 'Welcome, admin!' }))
```
## 🔍 Segurança e boas práticas

- **Segregação de responsabilidades:** controllers tratam requisições, services tratam lógica de negócio.
- **Criptografia de senha com bcrypt:** armazenamento seguro de senhas com hash e salt.
- **Tokens curtos + blacklist:** reduz janela de ataque e permite logout real.
- **Tratamento de erros JWT granular:** diferencia expired, invalid, e malformed.
- **Respostas HTTP semânticas:**
  - `401 Unauthorized` → Falha de autenticação (token ausente, inválido, expirado)
  - `403 Forbidden` → Acesso negado (usuário autenticado, mas sem permissão)
- **Variáveis sensíveis no .env** (`JWT_SECRET`, `JWT_EXPIRES`, `DATABASE_URL`)

## Conceitos técnicos aprofundados

### Stateless vs Stateful Auth

- **Stateful (com sessões):** o servidor mantém estado (ex: sessionID no Redis).
- **Stateless (JWT):** o estado é transportado no próprio token, eliminando dependência de armazenamento.

### Estrutura do JWT

`header.payload.signature`

- **Header:** algoritmo e tipo (`alg`, `typ`)
- **Payload:** dados do usuário e claims (`sub`, `exp`, `role`)
- **Signature:** HMAC do header + payload + segredo

Exemplo de payload:
```json
  {
    "sub": "652b1...",
    "name": "thaispinheiro",
    "role": "admin",
    "iat": 1730872000,
    "exp": 1730875600
  }
```
### Claims importantes usadas no projeto

- `sub` → Identificador do usuário (subject)
- `role` → Nível de permissão
- `iat` → Data de emissão (issued at)
- `exp` → Data de expiração (expiration)


## Endpoints principais

- `POST /login` — Login do usuário, retorna JWT.
- `POST /logout` — Logout, invalida o token atual.
- `POST /register` — Cadastro de novo usuário.
- `GET /my-account` — Retorna dados do usuário autenticado.
- `GET /admin` — Acesso restrito a usuários com papel `admin`.
- `GET /home` — Página protegida, qualquer usuário autenticado.

## Execução

1. **Clone o repositório**
2. **Configure o arquivo `.env`** com sua string de conexão do MongoDB e `JWT_SECRET`.
   ```yaml
   PORT=3000
   NODE_ENV=development
   DATABASE_URL=mongodb://localhost:27017/auth-jwt
   JWT_SECRET=supersecretkey
   JWT_EXPIRES=1h
   ```
3. **Instale as dependências**
   ```bash
   npm install
   ```
4. **Inicie o servidor em modo desenvolvimento**
   ```bash
   npm run dev
   ```

## Conhecimentos aplicados

- JWT e autenticação stateless
- Revogação de tokens via blacklist (Capped Collections no MongoDB)
- Autorização por papel (Role-Based Access Control - RBAC)
- Criptografia e segurança de senhas (bcrypt)
- Arquitetura limpa e modular (controller/service/plugin)
- Middleware, plugins e decorators no Fastify
- Tipagem e segurança com TypeScript
- Logs estruturados (audit trail com Winston)

---
## 📚 Referências técnicas

- [Login JWT em Node.js](https://www.rocketseat.com.br/blog/artigos/post/login-com-jwt-nodejs)
- [JWT Decoder](https://www.jwt.io/)
- [Fastify documentation](https://fastify.dev/)
- [Zod documentation](https://zod.dev/)
- [Capped collections, MongoDB documentation](https://www.mongodb.com/pt-br/docs/manual/core/capped-collections/)
- [Token based authentication with Fastify, JWT, and Typescript](https://medium.com/@atatijr/token-based-authentication-with-fastify-jwt-and-typescript-1fa5cccc63c5)
- [Autenticação JSON Web Token (JWT) em Node.js](https://www.luiztools.com.br/post/autenticacao-json-web-token-jwt-em-nodejs/)
---
