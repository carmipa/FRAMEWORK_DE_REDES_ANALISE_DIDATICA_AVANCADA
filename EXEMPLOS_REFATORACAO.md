# 🔧 EXEMPLOS DE REFATORAÇÃO
## Melhorando Logs e Exceções no Código Atual

---

## ANTES vs DEPOIS

### EXEMPLO 1: dominio_service.py

#### ANTES (Atual)

```python
def resolver_dns_com_cache(hostname):
    h = (hostname or "").strip().lower()
    if not h:
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    now = time.time()
    cached = _dns_cache.get(h)
    if cached and cached["expires_at"] > now:
        log_event("info", "dns_cache", status="hit", hostname=h)
        return cached["ip"]
    log_event("info", "dns_cache", status="miss", hostname=h)
    dns_started = time.perf_counter()
    future = _dns_executor.submit(socket.gethostbyname, h)
    try:
        ip = future.result(timeout=DNS_RESOLVE_TIMEOUT_SECONDS)
    except FuturesTimeoutError as exc:
        future.cancel()
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event(
            "warning",
            "dns_resolve",
            status="timeout",
            hostname=h,
            timeout_s=DNS_RESOLVE_TIMEOUT_SECONDS,
            elapsed_ms=elapsed_ms,
        )
        raise DnsResolucaoTimeoutError(
            "Timeout ao resolver DNS do domínio informado. Tente novamente em alguns segundos."
        ) from exc
    except socket.gaierror as exc:
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("warning", "dns_resolve", status="not_found", hostname=h, elapsed_ms=elapsed_ms)
        raise DnsResolucaoError(f"Não foi possível resolver o domínio/hostname informado: {h}") from exc
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        log_event("error", "dns_resolve", status="error", hostname=h, elapsed_ms=elapsed_ms, exc_info=True)
        raise DnsResolucaoError("Erro interno ao resolver DNS. Tente novamente.") from exc
    elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
    log_event("info", "dns_resolve", status="ok", hostname=h, ip=ip, elapsed_ms=elapsed_ms)
    _dns_cache[h] = {"ip": ip, "expires_at": now + DNS_CACHE_TTL_SECONDS}
    return ip
```

**Problemas:**
- Sem docstring
- Comportamento não documentado
- Lógica complexa sem comentários educacionais
- Padrão de erro não explicado

#### DEPOIS (Melhorado)

```python
"""
Serviço de Resolução DNS com Cache

Este módulo implementa resolução DNS com cache local, timeout e tratamento
de falhas. Serve como exemplo educacional de padrões de erro e logging.

FLUXO:
1. Valida entrada
2. Consulta cache
3. Se não houver, resolve via socket
4. Atualiza cache se bem-sucedido
5. Log em cada passo

PADRÕES DEMONSTRADOS:
- EntradaInvalidaError: Input inválido
- DnsResolucaoTimeoutError: Falha com retry possível
- DnsResolucaoError: Falha permanente
- log_event: Logging estruturado
"""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
import socket
import time

from backend.config import DNS_CACHE_TTL_SECONDS, DNS_RESOLVE_TIMEOUT_SECONDS
from backend.core.exceptions import (
    DnsResolucaoError,
    DnsResolucaoTimeoutError,
    EntradaInvalidaError
)
from backend.core.logging import log_event

_dns_cache = {}
_dns_executor = ThreadPoolExecutor(max_workers=2)


def resolver_dns_com_cache(hostname: str) -> str:
    """
    Resolve DNS com cache local.
    
    PADRÃO EDUCACIONAL DE TRATAMENTO DE ERROS:
    
    Fluxo de sucesso:
    1. Validar entrada
    2. Consultar cache (hit)
    3. Retornar resultado
    
    Fluxo com falha transitória (com retry):
    1. Tentar DNS live
    2. Timeout → DnsResolucaoTimeoutError
    3. Usuário pode retentar
    
    Fluxo com falha permanente:
    1. Tentar DNS live
    2. Domínio não existe → DnsResolucaoError
    3. Usuário não deve retentar
    
    Args:
        hostname: FQDN ou hostname (ex: "google.com")
    
    Returns:
        str: Endereço IP (ex: "142.251.41.14")
    
    Raises:
        EntradaInvalidaError: Hostname vazio ou inválido
        DnsResolucaoTimeoutError: DNS demorou demais (pode retentar)
        DnsResolucaoError: Domínio não existe ou erro desconhecido
    
    Examples:
        >>> resolver_dns_com_cache("google.com")
        '142.251.41.14'
        
        >>> resolver_dns_com_cache("")
        EntradaInvalidaError: Domínio/hostname vazio.
        
        >>> resolver_dns_com_cache("slow.server.test")
        DnsResolucaoTimeoutError: Timeout ao resolver DNS...
    """
    
    # ========================================================================
    # PASSO 1: VALIDAR ENTRADA
    # ========================================================================
    # Demonstra: EntradaInvalidaError (erro do usuário)
    
    h = (hostname or "").strip().lower()
    if not h:
        log_event("warning", "dns_resolve",
            status="entrada_invalida",
            motivo="hostname_vazio"
        )
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    
    # ========================================================================
    # PASSO 2: CONSULTAR CACHE
    # ========================================================================
    # Demonstra: Cache como fallback
    
    now = time.time()
    cached = _dns_cache.get(h)
    
    if cached and cached["expires_at"] > now:
        # ✅ Cache hit! Retorna imediatamente
        log_event("info", "dns_resolve",
            status="cache_hit",
            hostname=h,
            ip=cached["ip"],
            ttl_restante_s=int(cached["expires_at"] - now)
        )
        return cached["ip"]
    
    # Cache expirado ou não existe
    log_event("info", "dns_resolve",
        status="cache_miss",
        hostname=h
    )
    
    # ========================================================================
    # PASSO 3: RESOLVER DNS (com timeout)
    # ========================================================================
    # Demonstra: Tratamento de 3 tipos de erro diferentes
    
    dns_started = time.perf_counter()
    future = _dns_executor.submit(socket.gethostbyname, h)
    
    try:
        # Executa DNS em thread separada com timeout
        ip = future.result(timeout=DNS_RESOLVE_TIMEOUT_SECONDS)
        
    except FuturesTimeoutError as exc:
        # ⏱️ ERRO 1: Timeout (falha transitória - pode retentar)
        # Demonstra: DnsResolucaoTimeoutError
        
        future.cancel()
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        
        log_event("warning", "dns_resolve",
            status="timeout",
            hostname=h,
            timeout_s=DNS_RESOLVE_TIMEOUT_SECONDS,
            elapsed_ms=elapsed_ms
        )
        
        # Levanta exceção específica para timeouts
        # Permite ao cliente saber: "pode retentar com outro servidor DNS"
        raise DnsResolucaoTimeoutError(
            "Timeout ao resolver DNS do domínio informado. Tente novamente em alguns segundos."
        ) from exc
        
    except socket.gaierror as exc:
        # 🔍 ERRO 2: Domínio não existe (falha permanente)
        # Demonstra: DnsResolucaoError com log WARNING (erro esperado)
        
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        
        log_event("warning", "dns_resolve",
            status="nao_encontrado",
            hostname=h,
            elapsed_ms=elapsed_ms
        )
        
        # Levanta exceção específica para DNS failures
        # Permite ao cliente saber: "domínio não existe, não retente"
        raise DnsResolucaoError(
            f"Não foi possível resolver o domínio/hostname informado: {h}"
        ) from exc
        
    except Exception as exc:
        # 🛑 ERRO 3: Erro inesperado (problema de infraestrutura)
        # Demonstra: Exception genérica com log ERROR
        
        elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
        
        log_event("error", "dns_resolve",
            status="erro_inesperado",
            hostname=h,
            erro=type(exc).__name__,
            elapsed_ms=elapsed_ms,
            exc_info=True  # ← Inclui stack trace completo
        )
        
        # Levanta exceção genérica (pode ser retry)
        raise DnsResolucaoError(
            "Erro interno ao resolver DNS. Tente novamente."
        ) from exc
    
    # ========================================================================
    # PASSO 4: ATUALIZAR CACHE (sucesso)
    # ========================================================================
    # Demonstra: Cache como fallback para futuras falhas
    
    elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
    
    log_event("info", "dns_resolve",
        status="ok",
        hostname=h,
        ip=ip,
        elapsed_ms=elapsed_ms
    )
    
    # Atualiza cache para próximas requisições
    _dns_cache[h] = {
        "ip": ip,
        "expires_at": now + DNS_CACHE_TTL_SECONDS
    }
    
    return ip


# ============================================================================
# EXEMPLOS DE USO (para testes educacionais)
# ============================================================================

if __name__ == "__main__":
    """
    Demonstra diferentes cenários de uso.
    
    Execute com:
        python -m backend.analise.dominio_service
    """
    
    print("=" * 70)
    print("EXEMPLO 1: Entrada Válida (sucesso)")
    print("=" * 70)
    try:
        ip = resolver_dns_com_cache("google.com")
        print(f"✅ IP: {ip}\n")
    except Exception as e:
        print(f"❌ Erro: {e}\n")
    
    print("=" * 70)
    print("EXEMPLO 2: Entrada Vazia (EntradaInvalidaError)")
    print("=" * 70)
    try:
        ip = resolver_dns_com_cache("")
        print(f"✅ IP: {ip}\n")
    except EntradaInvalidaError as e:
        print(f"❌ Erro do usuário: {e}\n")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}\n")
    
    print("=" * 70)
    print("EXEMPLO 3: Domínio Inválido (DnsResolucaoError)")
    print("=" * 70)
    try:
        ip = resolver_dns_com_cache("dominio-inexistente-99999.test")
        print(f"✅ IP: {ip}\n")
    except DnsResolucaoError as e:
        print(f"❌ Erro de DNS: {e} (não retente)\n")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}\n")
```

**Melhorias:**
- ✅ Docstring completa
- ✅ PADRÃO EDUCACIONAL documentado em comments
- ✅ 3 tipos de erro explicados
- ✅ Exemplos de uso
- ✅ Casos de teste educacionais

---

### EXEMPLO 2: exceptions.py

#### ANTES (Atual)

```python
class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""


class InfraestruturaError(RuntimeError):
    """Erro de infraestrutura/serviço interno."""


class DnsResolucaoError(InfraestruturaError):
    """Falha geral ao resolver DNS."""


class DnsResolucaoTimeoutError(DnsResolucaoError):
    """Timeout durante resolução DNS."""


class HistoricoPersistenciaError(InfraestruturaError):
    """Falha ao carregar/persistir histórico local."""
```

**Problemas:**
- Docstrings muito curtas
- Sem explicação de QUANDO usar
- Sem exemplos
- Sem documentação de causas

#### DEPOIS (Melhorado)

```python
"""
Exceções Personalizadas - Framework de Redes

Este módulo define a hierarquia de exceções usada em todo o backend.

HIERARQUIA:
    Exception (Python built-in)
        ├─ EntradaInvalidaError ← Erros do usuário
        └─ InfraestruturaError ← Erros internos
            ├─ DnsResolucaoError
            │   └─ DnsResolucaoTimeoutError
            ├─ HistoricoPersistenciaError
            └─ ... (outras)

REGRA DE OURO:
- EntradaInvalidaError: Usuário forneceu dados ruins
- InfraestruturaError: Sistema falhou internamente

USANDO ESTA HIERARQUIA:

```python
# Cliente pode capturar especificamente
try:
    resultado = operacao()
except DnsResolucaoTimeoutError:
    # Retentar com outro servidor
    resultado = operacao_alternativa()
except DnsResolucaoError:
    # Domínio não existe, não retente
    mostrar_erro("Domínio inválido")
except EntradaInvalidaError as e:
    # Usuário forneceu entrada inválida
    resposta_http(400, str(e))
except InfraestruturaError:
    # Erro interno, não é culpa do usuário
    resposta_http(500, "Erro interno. Tente novamente.")
```

DOCUMENTAÇÃO DE CADA EXCEÇÃO:

1. **Quando levanta**
2. **Causas possíveis**
3. **Como tratá-la**
4. **Exemplo de uso**
"""


class EntradaInvalidaError(ValueError):
    """
    Erro de validação de entrada fornecida pelo usuário.
    
    Levantada quando o usuário fornece dados que não passam na validação.
    A mensagem será exibida diretamente ao usuário (amigável).
    
    QUANDO LEVANTA:
    - Campo obrigatório está vazio
    - Formato inválido (ex: CIDR "192.168.1.999/24")
    - Tamanho inválido (ex: CIDR muito grande)
    - Tipo inválido (ex: esperava string, recebeu int)
    
    CAUSAS POSSÍVEIS:
    - Usuário digitou incorretamente
    - Frontend validação falhou
    - Bot ou ataque (dados malformados propositalmente)
    
    COMO TRATAR:
    - Retornar HTTP 400 Bad Request
    - Exibir mensagem ao usuário
    - NÃO retentar automaticamente
    - NÃO alertar administrador (é erro normal)
    
    EXEMPLO:
        def validar_cidr(cidr_str):
            if not cidr_str:
                raise EntradaInvalidaError("CIDR não pode estar vazio")
            if '/' not in cidr_str:
                raise EntradaInvalidaError("CIDR deve conter '/'")
            return cidr_str
        
        # Uso
        try:
            cidr = validar_cidr(user_input)
        except EntradaInvalidaError as e:
            return {"erro": str(e)}, 400  # HTTP 400
    
    DIFERENTE DE:
    - InfraestruturaError: Para erros internos (não causados pelo usuário)
    - ValueError: Para programadores (não levante diretamente, use EntradaInvalidaError)
    """


class InfraestruturaError(RuntimeError):
    """
    Erro de infraestrutura ou serviço interno.
    
    Levantada quando algo que DEVERIA funcionar falhou.
    NÃO é causada por input do usuário.
    
    QUANDO LEVANTA:
    - Banco de dados indisponível
    - API externa falhou
    - Disco cheio
    - Permissão insuficiente
    - Erro inesperado em operação crítica
    
    CAUSAS POSSÍVEIS:
    - Problema de rede
    - Serviço dependente down
    - Problema de configuração
    - Bug no código
    
    COMO TRATAR:
    - Retornar HTTP 500 Internal Server Error
    - Exibir mensagem genérica ao usuário (não técnica)
    - Pode retentar automaticamente (pode ser transitório)
    - ALERTAR administrador (problema de infraestrutura)
    
    EXEMPLO:
        def conectar_banco():
            try:
                conexao = banco.connect()
            except ConnectionError as exc:
                log_event("error", "banco_conexao_falhou", exc_info=True)
                raise InfraestruturaError(
                    "Banco de dados indisponível. Tente novamente."
                ) from exc
        
        # Uso
        try:
            resultado = conectar_banco()
        except InfraestruturaError:
            return {"erro": "Erro interno. Tente novamente."}, 500  # HTTP 500
    
    DIFERENTE DE:
    - EntradaInvalidaError: Para erros do usuário
    - RuntimeError: Para programadores (não levante diretamente, use InfraestruturaError)
    """


class DnsResolucaoError(InfraestruturaError):
    """
    Falha ao resolver DNS - problema de infraestrutura de DNS.
    
    Subclasse de InfraestruturaError (falha interna).
    
    QUANDO LEVANTA:
    - Domínio não existe
    - Servidor DNS indisponível
    - Rede indisponível
    - Firewall bloqueando DNS
    - Erro desconhecido em resolução
    
    CAUSAS POSSÍVEIS:
    - Usuário digitou domínio errado
    - Domínio foi deletado
    - ISP ou servidor DNS down
    - Firewall corporativo bloqueando
    
    COMO TRATAR:
    - Log warning (erro esperado)
    - Retornar mensagem: "Não consegui resolver o domínio"
    - Não retentar com o mesmo DNS (provavelmente não vai mudar)
    - Pode tentar DNS alternativo como fallback
    
    EXEMPLO:
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as exc:
            log_event("warning", "dns_falhou", hostname=hostname)
            raise DnsResolucaoError(
                f"Não consegui resolver: {hostname}"
            ) from exc
    
    DIFERENTE DE:
    - DnsResolucaoTimeoutError: Quando DNS demorou (pode retentar)
    - EntradaInvalidaError: Quando hostname é inválido (ex: vazio)
    
    NOTA:
    As causas podem ser:
    - Domínio não existe (permanente)
    - DNS down (temporário, tente outro DNS)
    Por isso pode ser transitório em alguns casos!
    """


class DnsResolucaoTimeoutError(DnsResolucaoError):
    """
    Timeout ao resolver DNS - servidor DNS não respondeu a tempo.
    
    Subclasse de DnsResolucaoError (que é subclasse de InfraestruturaError).
    
    QUANDO LEVANTA:
    - DNS não responde no tempo esperado (ex: 5 segundos)
    - Rede muito lenta
    - Servidor DNS sobrecarregado
    
    CAUSAS POSSÍVEIS:
    - Servidor DNS lento/distante
    - Conexão com internet instável
    - DNS do ISP ruim
    - DDoS no servidor DNS
    
    COMO TRATAR:
    - Log warning (erro esperado, pode ser transitório)
    - Retentar com outro servidor DNS
    - Aumentar timeout para próxima tentativa
    - Usar cache se disponível
    
    EXEMPLO:
        try:
            ip = socket.gethostbyname(hostname)
        except socket.timeout as exc:
            log_event("warning", "dns_timeout", hostname=hostname)
            raise DnsResolucaoTimeoutError(
                f"DNS timeout para {hostname}"
            ) from exc
        
        # Tratamento com retry
        try:
            ip = resolver_dns(hostname)
        except DnsResolucaoTimeoutError:
            # Tenta servidor DNS alternativo
            ip = resolver_dns_alternativo(hostname)
    
    DIFERENTE DE:
    - DnsResolucaoError: Quando DNS retornou erro (não timeout)
    - socket.timeout: Exceção built-in (não levante diretamente)
    
    IMPORTANTE:
    Este é o ÚNICO caso onde retentar pode funcionar!
    """


class HistoricoPersistenciaError(InfraestruturaError):
    """
    Falha ao carregar ou salvar histórico local.
    
    Subclasse de InfraestruturaError (falha de persistência).
    
    QUANDO LEVANTA:
    - Arquivo de histórico corrompido
    - Disco cheio
    - Permissão insuficiente para ler/escrever
    - Erro ao fazer parse JSON
    - Arquivo foi deletado enquanto lia
    
    CAUSAS POSSÍVEIS:
    - Problema de hardware (disco cheio)
    - Problema de permissões
    - Software outro modificando arquivo
    - Arquivo corrompido (crash anterior)
    
    COMO TRATAR:
    - Log error (problema de infraestrutura)
    - Retornar mensagem: "Histórico temporariamente indisponível"
    - Pode continuar sem histórico (degraded mode)
    - Avisar administrador para investigar disco/permissões
    
    EXEMPLO:
        try:
            historico = json.load(open("historico.json"))
        except (IOError, json.JSONDecodeError) as exc:
            log_event("error", "historico_leitura", exc_info=True)
            raise HistoricoPersistenciaError(
                "Histórico indisponível"
            ) from exc
    
    RECUPERAÇÃO:
    Se possível, operate sem histórico:
    ```python
    try:
        historico = carregar_historico()
    except HistoricoPersistenciaError:
        log_event("warning", "usando_modo_degradado")
        historico = []  # Vazio, continua mesmo assim
    ```
    """


if __name__ == "__main__":
    """
    Exemplos educacionais de uso de cada exceção.
    
    Execute com:
        python -m backend.core.exceptions
    """
    
    print("=" * 70)
    print("HIERARQUIA DE EXCEÇÕES")
    print("=" * 70)
    
    # Demonstrar hierarquia
    erros = [
        EntradaInvalidaError("User error"),
        DnsResolucaoError("DNS error"),
        DnsResolucaoTimeoutError("DNS timeout"),
        HistoricoPersistenciaError("File error")
    ]
    
    for erro in erros:
        print(f"\n{erro.__class__.__name__}:")
        print(f"  ├─ Tipo: {type(erro).__name__}")
        print(f"  ├─ isinstance EntradaInvalidaError: {isinstance(erro, EntradaInvalidaError)}")
        print(f"  ├─ isinstance InfraestruturaError: {isinstance(erro, InfraestruturaError)}")
        print(f"  └─ isinstance DnsResolucaoError: {isinstance(erro, DnsResolucaoError)}")
```

**Melhorias:**
- ✅ Docstring completa para cada exceção
- ✅ QUANDO levanta, CAUSAS e COMO TRATAR
- ✅ Exemplos de código
- ✅ Explicação de diferenças
- ✅ Guia de uso educacional

---

## 📊 CHECKLIST DE REFATORAÇÃO

### FASE 1: Documentação (2-3 horas)
- [ ] Expandir docstrings em exceptions.py
- [ ] Adicionar exemplos de código
- [ ] Criar logging_guide.md
- [ ] Criar exception_patterns.py

### FASE 2: Código Actual (4-5 horas)
- [ ] Aplicar padrão educacional em dominio_service.py
- [ ] Adicionar comentários em try/except
- [ ] Adicionar exemplos de uso
- [ ] Atualizar docstrings

### FASE 3: Revisão (1-2 horas)
- [ ] Testar exemplos educacionais
- [ ] Revisar com alunos
- [ ] Coletar feedback
- [ ] Refinar baseado em feedback

**Total Estimado:** 7-10 horas

---

## 🎯 IMPACTO ESPERADO

| Aspecto | Antes | Depois |
|---------|-------|--------|
| Clareza de exceções | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Documentação | ⭐ | ⭐⭐⭐⭐ |
| Exemplos práticos | ⭐ | ⭐⭐⭐⭐⭐ |
| Facilidade de aprendizado | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Consistência de logging | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |

---

**Próximos Passos:**
1. Revisitar `backend/core/exceptions.py` com nova documentação
2. Refatorar `backend/analise/dominio_service.py` com comentários educacionais
3. Padronizar outros módulos (cidr_service, geo_service, etc)
4. Criar testes educacionais que demonstram cada padrão
5. Incorporar em currículo/slides

