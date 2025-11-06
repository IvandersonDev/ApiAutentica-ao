# Como Testar o Throttling no Endpoint /me

## O que e Throttling?

Throttling limita quantas requisicoes um usuario pode fazer em um periodo de tempo.

**Configuracao atual:**
- Limite: **10 requisicoes por minuto**
- Janela de tempo: **60 segundos**

## Como Testar

### 1. Criar um Usuario

```bash
curl -X POST http://localhost:8080/api/v1/auth/signup ^
  -H "Content-Type: application/json" ^
  -d "{\"name\":\"Usuario Teste\",\"email\":\"teste@exemplo.com\",\"password\":\"Senha123!\"}"
```

### 2. Fazer login e obter o token

```bash
curl -X POST http://localhost:8080/api/v1/auth/login ^
  -H "Content-Type: application/json" ^
  -d "{\"email\":\"teste@exemplo.com\",\"password\":\"Senha123!\"}"
```

Guarde o valor retornado em `"token"`.

### 3. Acessar o Endpoint /me (10 vezes)

```bash
curl -X GET http://localhost:8080/api/v1/auth/me ^
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```

**Resposta esperada (primeiras 10 vezes):**
```json
{
  "id": 1,
  "email": "teste@exemplo.com",
  "name": "Usuario Teste",
  "createdAt": "2025-10-30T..."
}
```

### 4. Testar o Bloqueio (11a requisicao)

Execute pela 11a vez:

```bash
curl -X GET http://localhost:8080/api/v1/auth/me ^
  -H "Authorization: Bearer SEU_TOKEN_AQUI"
```

**Resposta esperada:**
```json
{
  "message": "Muitas requisicoes. Aguarde 1 minuto"
}
```

### 5. Aguardar 1 Minuto

Aguarde 60 segundos e tente novamente. Vai funcionar!

## Testando com PowerShell

```powershell
# Criar usuario
$signupBody = @{name="Usuario Teste";email="teste@exemplo.com";password="Senha123!"} | ConvertTo-Json
Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/signup" -Method POST -Body $signupBody -ContentType "application/json"

# Login
$loginBody = @{email="teste@exemplo.com";password="Senha123!"} | ConvertTo-Json
$loginResponse = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/login" -Method POST -Body $loginBody -ContentType "application/json"
$token = $loginResponse.token

# Testar /me 15 vezes
for ($i = 1; $i -le 15; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:8080/api/v1/auth/me" -Method GET -Headers @{Authorization="Bearer $token"}
        Write-Host "Requisicao ${i}: OK - $($response.email)" -ForegroundColor Green
    } catch {
        Write-Host "Requisicao ${i}: BLOQUEADA" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds 100
}
```

## Como Funciona o Throttling

### Logica Simples:

1. **Primeira requisicao:** Cria uma janela de 60 segundos
2. **Requisicoes 2-10:** Incrementa contador
3. **Requisicao 11:** BLOQUEADA!
4. **Apos 60 segundos:** Reseta e permite novamente

### Estrutura de Dados:

```java
Map<String, RequestInfo> requestCache
  |
  +-- "teste@exemplo.com" -> RequestInfo {
                               windowStart: 2025-10-30 21:00:00
                               requestCount: 10
                             }
```

### Timeline Exemplo:

```
21:00:00 - Req 1  -> windowStart = 21:00:00, count = 1  ✅
21:00:05 - Req 2  -> count = 2  ✅
21:00:10 - Req 3  -> count = 3  ✅
...
21:00:45 - Req 10 -> count = 10 ✅
21:00:50 - Req 11 -> count >= 10 ❌ BLOQUEADA!
21:01:01 - Req 12 -> Nova janela! count = 1 ✅
```

## Configuracao

Para alterar os limites, edite o arquivo:
`src/main/java/com/example/msauthentication/service/ThrottlingService.java`

```java
private static final int MAX_REQUESTS_PER_MINUTE = 10;  // Altere aqui
private static final long TIME_WINDOW_SECONDS = 60;      // Altere aqui
```

## Diferenca entre Rate Limit e Throttling

| Caracteristica | Rate Limit | Throttling |
|----------------|------------|------------|
| **O que limita** | Tentativas de login erradas | Requisicoes em geral |
| **Rota** | `/login` | `/me` |
| **Limite** | 3 tentativas | 10 requisicoes |
| **Tempo** | 10 minutos de bloqueio | 1 minuto (janela) |
| **Reset** | Login correto | Aguardar 60 segundos |

## Status HTTP

- **200 OK:** Requisicao permitida
- **404 Not Found:** Usuario nao existe
- **401 Unauthorized:** Email nao fornecido
- **429 Too Many Requests:** Throttling ativado

