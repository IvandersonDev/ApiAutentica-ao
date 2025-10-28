# MS-Authentication com Rate Limiting

## Funcionalidades Implementadas

### Rate Limiting
- **Bloqueio após 3 tentativas**: Após 3 tentativas de login falhadas, o usuário é bloqueado por 10 minutos
- **Configurável**: As configurações podem ser ajustadas no `application.properties`
- **Endpoint de status**: Verificar o status de bloqueio de um usuário

## Configurações

No arquivo `application.properties`:

```properties
# Rate Limiting Configuration
rate-limit.enabled=true
rate-limit.max-attempts=3
rate-limit.block-duration-minutes=10
```

## Endpoints Disponíveis

### 1. Login
```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "usuario@exemplo.com",
  "password": "senha123"
}
```

**Respostas possíveis:**
- `"logou"` - Login bem-sucedido
- `"errou"` - Senha incorreta (incrementa tentativas)
- `"nao existe"` - Usuário não encontrado
- `"email ruim"` - Email inválido
- `"bloqueado por X minutos"` - Usuário bloqueado por rate limiting
- `"bloqueado por 10 minutos após 3 tentativas"` - Usuário acabou de ser bloqueado

### 2. Cadastro
```
POST /api/v1/auth/signup
Content-Type: application/json

{
  "email": "usuario@exemplo.com",
  "password": "senha123",
  "doc_number": "12345678901",
  "username": "usuario",
  "full_name": "Nome Completo"
}
```

### 3. Status do Rate Limiting
```
GET /api/v1/auth/rate-limit-status?email=usuario@exemplo.com
```

**Resposta:**
```json
{
  "email": "usuario@exemplo.com",
  "isBlocked": true,
  "remainingMinutes": 8
}
```

## Como Funciona o Rate Limiting

1. **Primeira tentativa falhada**: Incrementa contador
2. **Segunda tentativa falhada**: Incrementa contador
3. **Terceira tentativa falhada**: Usuário é bloqueado por 10 minutos
4. **Login bem-sucedido**: Reseta o contador de tentativas
5. **Após o bloqueio expirar**: Usuário pode tentar novamente

## Executando a Aplicação

```bash
mvn spring-boot:run
```

A aplicação estará disponível em `http://localhost:8080`

## Testando o Rate Limiting

1. Faça 3 tentativas de login com senha incorreta
2. Na 3ª tentativa, você receberá a mensagem de bloqueio
3. Use o endpoint `/rate-limit-status` para verificar o tempo restante
4. Após 10 minutos, o usuário será desbloqueado automaticamente
5. Um login bem-sucedido reseta imediatamente o contador

