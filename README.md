# MS-Authentication com Protecoes Adicionais

## Visao Geral
Aplicacao Spring Boot que simula um microsservico de autenticacao com controles anti-abuso, criptografia simetrica de tokens e fluxo seguro de recuperacao de senha. Redis e utilizado como armazenamento de cache para rate limiting, throttling e tokens de recuperacao (com fallback em memoria para ambientes de desenvolvimento).

## Dependencias Principais
- Java 17
- Maven
- PostgreSQL (localhost:5432 por padrao)
- Redis (localhost:6379 por padrao)

## Configuracao
As configuracoes padrao podem ser ajustadas no arquivo `src/main/resources/application.properties`:

```properties
# Banco de dados
spring.datasource.url=jdbc:postgresql://localhost:5432/ms_auth
spring.datasource.username=postgres
spring.datasource.password=postgres
spring.sql.init.mode=never

# Rate limiting
rate-limit.enabled=true
rate-limit.max-attempts=3
rate-limit.block-duration-minutes=10

# Redis
spring.redis.host=localhost
spring.redis.port=6379

# Criptografia do token
token.encryption.secret=change-me-please-use-env
token.encryption.ttl-hours=24

# Recuperacao de senha
password-recovery.token-ttl-minutes=15
password-recovery.hmac-secret=change-me-too-use-env

# JPA
spring.jpa.hibernate.ddl-auto=update
spring.jpa.open-in-view=false
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
```

> **Importante:** sobrescreva os segredos por variaveis de ambiente no ambiente real.

## Endpoints Principais

### Auth
- `POST /api/v1/auth/signup` – Cadastro de usuario (nome, email e senha).
- `POST /api/v1/auth/login` – Login com rate limiting baseado em Redis. Retorna token simetricamente criptografado (AES/GCM).
- `GET /api/v1/auth/me` – Recupera informacoes do usuario autenticado. Possui throttling (10 req/min) com Redis.
- `GET /api/v1/auth/rate-limit-status?email=...` – Consulta status do bloqueio por tentativas incorretas.

### Recuperacao de Senha
- `POST /api/v1/auth/password-recovery/request` – Valida email/nome e gera token de recuperacao temporario. Para fins de teste o token e retornado na resposta; em producao deve ser enviado por canal seguro.
- `POST /api/v1/auth/password-recovery/validate` – Valida o token informado aplicando comparacao em tempo constante e limite de tentativas.
- `POST /api/v1/auth/password-recovery/reset` – Atualiza a senha caso o token seja valido. Invalida o token e reseta contadores.

## Executando
1. Inicie um servidor PostgreSQL local e garanta que o banco exista (exemplo: `CREATE DATABASE ms_auth;`).
2. Inicie um servidor Redis local (`redis-server`).
3. Execute a aplicacao:
   ```bash
   mvn spring-boot:run
   ```
4. A API ficara disponivel em `http://localhost:8080`.

## Colecao Postman
- Importar `postman/ms-authentication.postman_collection.json`.
- Ajustar variaveis (nome, email, senhas) conforme necessário.
- Executar os requests na ordem do grupo **Auth** e, em seguida, **Password Recovery** para validar os fluxos.

## Observacoes de Seguranca
- Os segredos presentes no `application.properties` sao valores placeholder e devem ser substituidos.
- Configure as credenciais do PostgreSQL via variaveis de ambiente ou profiles separados para evitar expor senhas.
- O schema e gerenciado automaticamente via `spring.jpa.hibernate.ddl-auto=update` (ajuste conforme o ambiente).
- A criptografia usa AES-256 em modo GCM com IV aleatorio por token.
- Token de recuperacao e armazenado com hash HMAC e validado com comparacao em tempo constante.
- Tentativas invalidas de recuperar senha sao limitadas (redis + TTL) para mitigar brute force.
