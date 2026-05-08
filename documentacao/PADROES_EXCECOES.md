# 🎓 PADRÕES DE TRATAMENTO DE EXCEÇÕES
## Guia Educacional Prático - Backend

---

## 📌 ÍNDICE RÁPIDO

1. [Padrão 1: Entrada Inválida](#padrão-1-entrada-inválida)
2. [Padrão 2: Erro Esperado com Fallback](#padrão-2-erro-esperado-com-fallback)
3. [Padrão 3: Erro Inesperado](#padrão-3-erro-inesperado)
4. [Padrão 4: Múltiplas Camadas](#padrão-4-múltiplas-camadas)
5. [Padrão 5: Retry com Exponential Backoff](#padrão-5-retry-com-exponential-backoff)

---

## PADRÃO 1: ENTRADA INVÁLIDA

**Uso:** Quando usuário fornece dados ruins  
**Exceção:** `EntradaInvalidaError`  
**Log:** `INFO` ou `WARNING`

### Exemplo: Validar CIDR

```python
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event
import ipaddress

def processar_cidr(cidr_str: str) -> dict:
    """
    Processa uma string CIDR fornecida pelo usuário.
    
    Args:
        cidr_str: String como "192.168.1.0/24"
    
    Returns:
        dict com informações da rede
    
    Raises:
        EntradaInvalidaError: Se CIDR está inválido
    
    PADRÃO EDUCACIONAL:
    1. Validar entrada
    2. Se inválida → log + raise EntradaInvalidaError
    3. Se válida → processar normalmente
    """
    
    # PASSO 1: Validar entrada é None ou vazia?
    cidr_str = (cidr_str or "").strip()
    if not cidr_str:
        log_event("warning", "cidr_invalida",
            status="vazia",
            entrada="<vazio>"
        )
        raise EntradaInvalidaError("CIDR não pode estar vazio")
    
    # PASSO 2: Tentar parse
    try:
        rede = ipaddress.ip_network(cidr_str, strict=False)
    except ValueError as exc:
        # ValueError = Formato inválido (built-in do Python)
        # Convertemos para EntradaInvalidaError (nosso custom error)
        log_event("warning", "cidr_invalida",
            status="formato_invalido",
            entrada=cidr_str,
            erro=str(exc)[:50]
        )
        raise EntradaInvalidaError(f"CIDR inválido: {cidr_str}") from exc
    
    # PASSO 3: Validações lógicas
    if rede.num_addresses > 1000000:
        log_event("warning", "cidr_invalida",
            status="muito_grande",
            entrada=cidr_str,
            num_addresses=rede.num_addresses
        )
        raise EntradaInvalidaError("CIDR muito grande (máx 1M addresses)")
    
    # PASSO 4: Sucesso!
    log_event("info", "cidr_validada",
        status="ok",
        entrada=cidr_str,
        num_addresses=rede.num_addresses
    )
    
    return {
        "rede": str(rede.network_address),
        "mascara": str(rede.netmask),
        "hosts": rede.num_addresses - 2  # Exclui network e broadcast
    }


# TESTE - Como chamar?
if __name__ == "__main__":
    # ✅ Entrada válida
    try:
        resultado = processar_cidr("192.168.1.0/24")
        print(f"✅ Sucesso: {resultado}")
    except EntradaInvalidaError as e:
        print(f"❌ Erro do usuário: {e}")
    
    # ❌ Entrada inválida
    try:
        resultado = processar_cidr("192.168.1.999/24")
        print(f"✅ Sucesso: {resultado}")
    except EntradaInvalidaError as e:
        print(f"❌ Erro do usuário: {e}")
    
    # ❌ Entrada vazia
    try:
        resultado = processar_cidr("")
        print(f"✅ Sucesso: {resultado}")
    except EntradaInvalidaError as e:
        print(f"❌ Erro do usuário: {e}")
```

### Logs Esperados

```
warning | cybernet | req=abc123 | evento=cidr_invalida status=vazia entrada=<vazio>
warning | cybernet | req=def456 | evento=cidr_invalida status=formato_invalido entrada=192.168.1.999/24 erro=Expected 4 octets
warning | cybernet | req=ghi789 | evento=cidr_invalida status=muito_grande entrada=0.0.0.0/1 num_addresses=2147483648
info    | cybernet | req=jkl012 | evento=cidr_validada status=ok entrada=192.168.1.0/24 num_addresses=254
```

---

## PADRÃO 2: ERRO ESPERADO COM FALLBACK

**Uso:** Quando operação PODE falhar, mas temos plano B  
**Exceção:** Catch específica, tenta fallback, depois custom exception se necessário  
**Log:** `INFO` (fallback), `WARNING` (fallback usado)

### Exemplo: DNS com Cache

```python
from backend.core.logging import log_event
from backend.core.exceptions import DnsResolucaoError
import socket
import time

# Simulando cache local
_dns_cache = {}
_dns_cache_ttl_seconds = 3600

def resolver_dns_com_fallback(hostname: str) -> str:
    """
    Resolve DNS com fallback para cache.
    
    PADRÃO EDUCACIONAL:
    1. Tentar operação preferida
    2. Se falhar de forma esperada → usar fallback
    3. Se fallback também falhar → raise custom exception
    
    Sequência:
    └─ Tentar DNS live
       ├─ Sucesso? → retorna + loga INFO
       └─ Falha? → tenta cache
           ├─ Cache tem? → retorna + loga WARNING
           └─ Cache não tem? → raise DnsResolucaoError
    """
    
    hostname = (hostname or "").strip().lower()
    if not hostname:
        raise DnsResolucaoError("Hostname não pode estar vazio")
    
    # PASSO 1: Tentar DNS live
    inicio = time.perf_counter()
    try:
        ip = socket.gethostbyname(hostname)
        elapsed_ms = int((time.perf_counter() - inicio) * 1000)
        
        # ✅ Sucesso! Atualizar cache
        _dns_cache[hostname] = {
            "ip": ip,
            "expira_em": time.time() + _dns_cache_ttl_seconds
        }
        
        log_event("info", "dns_resolve",
            status="ok",
            hostname=hostname,
            ip=ip,
            elapsed_ms=elapsed_ms,
            source="live"
        )
        return ip
        
    except socket.gaierror as exc:
        # ⚠️ Falha esperada (domínio não existe ou rede indisponível)
        elapsed_ms = int((time.perf_counter() - inicio) * 1000)
        
        log_event("warning", "dns_resolve",
            status="falhou_live",
            hostname=hostname,
            elapsed_ms=elapsed_ms,
            erro=type(exc).__name__
        )
        
        # PASSO 2: Tentar fallback (cache)
        cached = _dns_cache.get(hostname)
        if cached and cached["expira_em"] > time.time():
            # ✅ Cache tem valor válido
            ip = cached["ip"]
            
            log_event("warning", "dns_resolve",
                status="usando_cache",
                hostname=hostname,
                ip=ip
            )
            return ip
        
        # PASSO 3: Sem fallback disponível
        log_event("error", "dns_resolve",
            status="falha_total",
            hostname=hostname,
            exc_info=True
        )
        raise DnsResolucaoError(
            f"Não consegui resolver {hostname} e não há cache"
        ) from exc


# TESTE
if __name__ == "__main__":
    # ✅ DNS válido
    try:
        ip = resolver_dns_com_fallback("google.com")
        print(f"✅ Resolvido: google.com → {ip}")
    except DnsResolucaoError as e:
        print(f"❌ Erro: {e}")
    
    # ❌ DNS inválido (tenta cache)
    try:
        ip = resolver_dns_com_fallback("dominio-inexistente-12345.test")
    except DnsResolucaoError as e:
        print(f"❌ Erro: {e}")
```

---

## PADRÃO 3: ERRO INESPERADO

**Uso:** Quando algo que DEVERIA funcionar falhou  
**Exceção:** Catch genérica, log com stack trace, raise custom exception  
**Log:** `ERROR` (sempre com exc_info=True)

### Exemplo: Acesso a Banco de Dados

```python
from backend.core.logging import log_event
from backend.core.exceptions import InfraestruturaError

def carregar_usuario_do_banco(usuario_id: int) -> dict:
    """
    Carrega usuário do banco de dados.
    
    PADRÃO EDUCACIONAL:
    1. Tentar operação
    2. Se erro inesperado → log ERROR com stack trace
    3. Nunca expor detalhes técnicos ao usuário
    
    Porque "inesperado"?
    - Banco DEVERIA estar disponível
    - Query DEVERIA estar correta
    - Se falhou = problema de infraestrutura
    """
    
    if not isinstance(usuario_id, int) or usuario_id <= 0:
        raise EntradaInvalidaError("ID do usuário deve ser inteiro positivo")
    
    inicio = time.perf_counter()
    
    try:
        # Simular query ao banco
        query = f"SELECT * FROM usuarios WHERE id = {usuario_id}"
        resultado = executa_query_banco(query)  # Função fictícia
        
        elapsed_ms = int((time.perf_counter() - inicio) * 1000)
        log_event("info", "banco_query",
            status="ok",
            query="select_usuario",
            usuario_id=usuario_id,
            elapsed_ms=elapsed_ms
        )
        return resultado
        
    except ConnectionError as exc:
        # Banco de dados está down = erro de infraestrutura
        elapsed_ms = int((time.perf_counter() - inicio) * 1000)
        
        log_event("error", "banco_query",
            status="connection_error",
            query="select_usuario",
            usuario_id=usuario_id,
            elapsed_ms=elapsed_ms,
            exc_info=True  # ← IMPORTANTE: Inclui stack trace completo
        )
        
        # Nunca exposar detalhes técnicos ao usuário!
        raise InfraestruturaError(
            "Banco de dados temporariamente indisponível"
        ) from exc
        
    except Exception as exc:
        # Qualquer outro erro inesperado
        elapsed_ms = int((time.perf_counter() - inicio) * 1000)
        
        log_event("error", "banco_query",
            status="erro_inesperado",
            query="select_usuario",
            usuario_id=usuario_id,
            erro=type(exc).__name__,
            mensagem=str(exc)[:100],
            elapsed_ms=elapsed_ms,
            exc_info=True  # ← Stack trace para debug
        )
        
        # Mensagem genérica, sem expor detalhes
        raise InfraestruturaError(
            "Erro ao processar solicitação. Tente novamente."
        ) from exc
```

---

## PADRÃO 4: MÚLTIPLAS CAMADAS

**Uso:** Quando há validação em múltiplas camadas  
**Flow:** Web Layer → Service Layer → Core Layer

### Exemplo: Completo

```python
# ============================================================
# CAMADA 1: ENTRADA (Web/API)
# ============================================================

from flask import request, jsonify
from backend.core.exceptions import EntradaInvalidaError, InfraestruturaError

@app.route('/analisar/cidr', methods=['POST'])
def api_analisar_cidr():
    """
    Endpoint da API - recebe CIDR do usuário.
    
    RESPONSABILIDADE:
    1. Validar formato básico (ex: é string?)
    2. Chamar serviço
    3. Tratar EntradaInvalidaError → retorna 400
    4. Tratar InfraestruturaError → retorna 500
    """
    
    # Validação básica da request
    if not request.json or 'cidr' not in request.json:
        return jsonify({
            "erro": "Campo 'cidr' é obrigatório"
        }), 400
    
    cidr_input = request.json['cidr']
    
    try:
        # Chama serviço (camada 2)
        resultado = servico_analisar_cidr(cidr_input)
        return jsonify(resultado), 200
        
    except EntradaInvalidaError as e:
        # ✅ Erro do usuário → 400 Bad Request
        return jsonify({"erro": str(e)}), 400
        
    except InfraestruturaError as e:
        # ❌ Erro interno → 500 Server Error
        return jsonify({"erro": "Erro interno. Tente novamente."}), 500


# ============================================================
# CAMADA 2: SERVIÇO (Business Logic)
# ============================================================

from backend.core.logging import log_event

def servico_analisar_cidr(cidr_str: str) -> dict:
    """
    Serviço que analisa CIDR.
    
    RESPONSABILIDADE:
    1. Validar entrada (pode usar exceções custom)
    2. Chamar operações core
    3. Orquestrar lógica
    """
    
    log_event("info", "servico_cidr", status="start", cidr=cidr_str[:50])
    
    # Validação (pode raising EntradaInvalidaError)
    cidr_validado = validar_cidr_formato(cidr_str)  # Camada 3
    
    # Processar
    try:
        resultado = core_analisar_rede(cidr_validado)
        log_event("info", "servico_cidr", status="ok")
        return resultado
        
    except Exception as exc:
        log_event("error", "servico_cidr", 
            status="erro",
            exc_info=True
        )
        # Não expor erro específico
        raise InfraestruturaError("Erro ao analisar CIDR") from exc


# ============================================================
# CAMADA 3: CORE (Operações primitivas)
# ============================================================

def validar_cidr_formato(cidr_str: str) -> str:
    """
    Valida formato CIDR básico.
    
    Raises:
        EntradaInvalidaError: Se formato inválido
    """
    
    cidr_str = (cidr_str or "").strip()
    if not cidr_str:
        raise EntradaInvalidaError("CIDR vazio")
    
    if '/' not in cidr_str:
        raise EntradaInvalidaError("CIDR deve conter '/'")
    
    partes = cidr_str.split('/')
    if len(partes) != 2:
        raise EntradaInvalidaError("CIDR com formato inválido")
    
    return cidr_str


def core_analisar_rede(cidr_str: str) -> dict:
    """
    Analisa rede (operação core).
    
    Pode raise InfraestruturaError se algo deu errado internamente.
    """
    
    try:
        rede = ipaddress.ip_network(cidr_str, strict=False)
        return {
            "rede": str(rede.network_address),
            "mascara": str(rede.netmask),
            "hosts": rede.num_addresses - 2
        }
    except Exception as exc:
        # Erro inesperado em operação core
        log_event("error", "core_analisar_rede",
            cidr=cidr_str,
            exc_info=True
        )
        raise InfraestruturaError("Erro ao analisar rede") from exc
```

---

## PADRÃO 5: RETRY COM EXPONENTIAL BACKOFF

**Uso:** Para operações que podem ser transitórias  
**Exceção:** Retry automático, depois raise se esgotar tentativas

### Exemplo: DNS com Retry

```python
import time
from backend.core.logging import log_event
from backend.core.exceptions import DnsResolucaoError, DnsResolucaoTimeoutError

def resolver_dns_com_retry(
    hostname: str,
    max_tentativas: int = 3,
    timeout_inicial_s: float = 5.0
) -> str:
    """
    Resolve DNS com retry e backoff exponencial.
    
    PADRÃO EDUCACIONAL:
    - Tenta múltiplas vezes
    - Cada falha espera mais tempo (exponential backoff)
    - Log de cada tentativa
    - Depois desiste com descrição clara
    
    Backoff exemplo:
    - Tentativa 1: espera 5s
    - Tentativa 2: espera 10s (5s * 2)
    - Tentativa 3: espera 20s (10s * 2)
    - Total: até 35s de espera
    """
    
    hostname = (hostname or "").strip().lower()
    
    for tentativa in range(1, max_tentativas + 1):
        log_event("info", "dns_retry",
            status="tentando",
            hostname=hostname,
            tentativa=tentativa,
            max_tentativas=max_tentativas
        )
        
        inicio = time.perf_counter()
        try:
            ip = socket.gethostbyname(hostname)
            elapsed_ms = int((time.perf_counter() - inicio) * 1000)
            
            log_event("info", "dns_retry",
                status="ok",
                hostname=hostname,
                ip=ip,
                tentativa=tentativa,
                elapsed_ms=elapsed_ms
            )
            return ip
            
        except socket.timeout:
            # Timeout = pode ser transitório, tenta de novo
            elapsed_ms = int((time.perf_counter() - inicio) * 1000)
            
            if tentativa < max_tentativas:
                espera = timeout_inicial_s * (2 ** (tentativa - 1))
                
                log_event("warning", "dns_retry",
                    status="timeout_retentar",
                    hostname=hostname,
                    tentativa=tentativa,
                    espera_s=espera,
                    elapsed_ms=elapsed_ms
                )
                time.sleep(espera)  # Exponential backoff
            else:
                log_event("error", "dns_retry",
                    status="timeout_final",
                    hostname=hostname,
                    tentativa=tentativa,
                    max_tentativas=max_tentativas
                )
                raise DnsResolucaoTimeoutError(
                    f"DNS timeout após {max_tentativas} tentativas"
                )
                
        except socket.gaierror as exc:
            # Domínio não existe = não vai melhorar com retry
            log_event("error", "dns_retry",
                status="nao_encontrado",
                hostname=hostname,
                tentativa=tentativa
            )
            raise DnsResolucaoError(f"Domínio não existe: {hostname}") from exc
```

---

## 🎯 RESUMO: QUANDO USAR CADA PADRÃO

| Padrão | Situação | Exceção | Log |
|--------|----------|---------|-----|
| 1 | Entrada inválida | `EntradaInvalidaError` | WARNING |
| 2 | Pode falhar, temos fallback | Custom + fallback | INFO/WARNING |
| 3 | Deveria funcionar | `InfraestruturaError` | ERROR |
| 4 | Múltiplas camadas | Propagar + transformar | Cada camada |
| 5 | Pode ser transitório | Retry automático | INFO (cada tentativa) |

---

## ✅ ANTI-PATTERNS (O QUE NÃO FAZER)

### ❌ ANTI-PATTERN 1: Swallow Exception

```python
# ❌ ERRADO - Esconde o erro!
try:
    resultado = operacao()
except Exception:
    pass  # NUNCA faça isso!
    # Alguém mais tarde não vai entender por que falhou
```

**Correto:**
```python
# ✅ CORRETO - Loga e re-lança
try:
    resultado = operacao()
except Exception as exc:
    log_event("error", "operacao", exc_info=True)
    raise  # Re-lança a exceção
```

---

### ❌ ANTI-PATTERN 2: Catch GenericException

```python
# ❌ ERRADO - Muito genérico!
try:
    resultado = socket.gethostbyname(hostname)
except:  # Pega TUDO!
    return "erro"
```

**Correto:**
```python
# ✅ CORRETO - Específico
try:
    resultado = socket.gethostbyname(hostname)
except socket.timeout:
    # Timeout específico
    log_event("warning", "dns_timeout")
    raise DnsResolucaoTimeoutError(...) from exc
except socket.gaierror as exc:
    # Domínio não encontrado
    log_event("warning", "dns_not_found")
    raise DnsResolucaoError(...) from exc
```

---

### ❌ ANTI-PATTERN 3: Lose Exception Context

```python
# ❌ ERRADO - Perde informação
except Exception:
    raise EntradaInvalidaError("Entrada inválida")
    # Original exception foi perdida!
```

**Correto:**
```python
# ✅ CORRETO - Preserva contexto
except Exception as exc:
    raise EntradaInvalidaError("Entrada inválida") from exc
    # "from exc" mantém a chain!
```

---

### ❌ ANTI-PATTERN 4: Expose Technical Details

```python
# ❌ ERRADO - Mostra detalhes técnicos!
except Exception as exc:
    return {
        "erro": str(exc),  # Pode conter detalhes sensíveis!
        "tipo": type(exc).__name__
    }
```

**Correto:**
```python
# ✅ CORRETO - Mensagem amigável
except Exception as exc:
    log_event("error", "operacao", exc_info=True)  # Log detalhes
    return {"erro": "Erro ao processar. Tente novamente."}  # Genérico
```

---

## 📖 LEITURA RECOMENDADA

- [PEP 3134 - Exception Chaining](https://www.python.org/dev/peps/pep-3134/)
- [Python Logging How To](https://docs.python.org/3/howto/logging.html)
- [12 Factor App - Logs](https://12factor.net/logs)

---

**Última atualização:** 08/05/2026  
**Versão:** 1.0 - Inicial
