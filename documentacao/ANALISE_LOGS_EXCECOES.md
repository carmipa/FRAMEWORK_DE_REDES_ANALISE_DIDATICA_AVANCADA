# 📊 ANÁLISE: LOGS E TRATAMENTO DE EXCEÇÕES
## Framework de Redes - Análise Didática Avançada

**Data da Análise:** 08/05/2026  
**Arquivos Analisados:**
- `backend/core/logging.py` (172 linhas)
- `backend/core/exceptions.py` (19 linhas)
- Usos em `backend/analise/` (30+ chamadas)

**Status Geral:** ⚠️ **BOM POTENCIAL - NECESSITA DOCUMENTAÇÃO DIDÁTICA**

---

## 📋 RESUMO EXECUTIVO

O sistema atual de logs e exceções possui uma implementação sólida com recursos avançados (cores, estrutura de eventos, request tracking), mas **falta documentação educacional** para que alunos entendam os conceitos.

**Conformidade Didática:** 60% | **Recomendação:** Implementar guia de boas práticas + exemplos comentados

---

## ✅ PONTOS FORTES

### 1. **Estrutura de Logging Profissional**
```python
✅ Sistema de formatação UTC
✅ Colorização ANSI para melhor leitura
✅ Request ID tracking (rastreabilidade)
✅ Logging estruturado (evento + campos)
✅ Suporte a múltiplos níveis (DEBUG, INFO, WARNING, ERROR, CRITICAL)
✅ Integração com audit trail
```

### 2. **Exceções Bem Hierarquizadas**
```python
EntradaInvalidaError          ← Erros do usuário
InfraestruturaError           ← Erros internos
  ├─ DnsResolucaoError        ← DNS específico
  ├─ DnsResolucaoTimeoutError ← Timeout específico
  └─ HistoricoPersistenciaError
```

### 3. **Implementação Prática Coerente**
- Uso consistente de `log_event()` para eventos estruturados
- Pattern claro de try/except/raise
- Métrica de tempo (elapsed_ms) nos logs
- Fallback inteligente (exemplo: cache DNS hit/miss)

### 4. **Segurança Considerada**
- Limpeza de valores None antes de logar
- Proteção contra caracteres especiais em ANSI
- Não expõe detalhes técnicos ao usuário

---

## ⚠️ PROBLEMAS DIDÁTICOS IDENTIFICADOS

### **1. FALTA DE DOCUMENTAÇÃO NAS EXCEÇÕES** ❌
**Severidade:** ALTA

**Problema Atual:**
```python
class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""
```

**Por que é um problema:**
- Não explicação QUANDO usar
- Não há exemplo de uso
- Aluno não sabe a diferença entre `ValueError` e `EntradaInvalidaError`
- Sem docstring de retorno esperado

**Recomendação:**
```python
class EntradaInvalidaError(ValueError):
    """
    Erro de validação de entrada - informado ao usuário final.
    
    Levantada quando o usuário fornece dados inválidos (ex: IP malformado).
    A mensagem será exibida diretamente ao usuário.
    
    QUANDO USAR:
    - Input do usuário não passa na validação
    - Campo obrigatório está vazio
    - Formato inválido (ex: CIDR inválido)
    
    EXEMPLO:
        def validar_ip(ip_str):
            if not isinstance(ip_str, str):
                raise EntradaInvalidaError("IP deve ser uma string")
            if not re.match(r'^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$', ip_str):
                raise EntradaInvalidaError(f"IP inválido: {ip_str}")
    
    Exceção relacionada:
        - InfraestruturaError: Para erros internos (não causados pelo usuário)
    """
```

---

### **2. LOGGING INCONSISTENTE** ⚠️
**Severidade:** MÉDIA

**Problema Atual:**

Há dois padrões misturados:

```python
# PADRÃO 1: log_event() - Estruturado (BOM)
log_event("info", "dns_cache", status="hit", hostname=h)

# PADRÃO 2: logger.warning() - String (CONFUSO)
logger.warning("evento=calc status=invalid_input modo=cidr campo=cidr")
```

**Por que é confuso:**
- Aluno não sabe qual usar
- Padrão 2 é repetitivo e propenso a erros
- Não há razão técnica para manter ambos

**Recomendação:**

Padronizar em torno de `log_event()` com guia educacional:

```markdown
## Guia de Logging

### Usar log_event() SEMPRE que possível

✅ BOM - Estruturado:
```python
log_event("info", "dns_resolve", 
    status="ok", 
    hostname=hostname,
    ip=result_ip,
    elapsed_ms=elapsed_time
)
```

❌ EVITAR - String concatenada:
```python
logger.warning(f"evento=calc status=invalid ip={ip}")
```

### Por que log_event()?
1. **Estruturado**: Campos klaros e validados
2. **Auditável**: Integra com audit_service
3. **Parseável**: Ferramentas conseguem ler
4. **Seguro**: Sanitiza valores None
```

---

### **3. FALTA DE TRATAMENTO DE EXCEÇÃO EDUCACIONAL** ❌
**Severidade:** ALTA

**Problema Atual:**

Padrão repetitivo sem documentação:

```python
except socket.gaierror as exc:
    elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
    log_event("warning", "dns_resolve", status="not_found", hostname=h, elapsed_ms=elapsed_ms)
    raise DnsResolucaoError(f"...") from exc
except Exception as exc:
    elapsed_ms = int((time.perf_counter() - dns_started) * 1000)
    log_event("error", "dns_resolve", status="error", hostname=h, elapsed_ms=elapsed_ms, exc_info=True)
    raise DnsResolucaoError("...") from exc
```

**O que falta:**
- Não há explicação do pattern
- Aluno não entende por que `from exc`
- Não mostra alternativas de tratamento
- Sem documentação sobre níveis (warning vs error)

**Recomendação:**

Criar módulo de educação com padrões comentados:

```python
"""
PADRÃO DE TRATAMENTO DE EXCEÇÕES - Backend

Este módulo documenta os padrões recomendados para tratamento de exceções
com logging adequado.
"""

# PADRÃO 1: Erro esperado → Log WARNING + raise custom exception
try:
    result = operacao_que_pode_falhar()
except SpecificError as exc:
    # WARNING: Erro esperado que deveria ter sido tratado
    log_event("warning", "operacao_falhou", 
        erro=type(exc).__name__,
        mensagem=str(exc)[:100]  # Limita tamanho
    )
    # Levanta exceção custom para tratamento na camada superior
    raise CustomError("Mensagem amigável ao usuário") from exc

# PADRÃO 2: Erro inesperado → Log ERROR + raise custom exception
try:
    resultado = operacao_critica()
except Exception as exc:
    # ERROR: Algo inesperado aconteceu
    log_event("error", "operacao_critica_falhou",
        erro=type(exc).__name__,
        exc_info=True  # Inclui stack trace
    )
    # Levanta exceção sem expor detalhes técnicos
    raise InfraestruturaError("Erro interno. Contate o suporte.") from exc

# PADRÃO 3: Recuperação possível → Log INFO
try:
    resultado = acesso_com_fallback()
except CacheError:
    log_event("info", "cache_indisponivel", usando="fallback")
    # Tenta fallback
    resultado = fallback_seguro()


# O QUE SIGNIFICA "raise ... from exc":
# 
# raise CustomError() from exc
#         ↑                ↑
#         |                └─ PRESERVA a exceção original
#         |                   (importante para debug)
#         |
#         └─ Levanta nova exceção com melhor contexto
#
# RESULTADO: Exception chain (chain de exceções)
#   CustomError: Mensagem amigável
#   └─ caused by: OriginalError: Detalhes técnicos
#
# Permite logging completo + mensagem segura ao usuário
```

---

### **4. NÍVEIS DE LOG NÃO DOCUMENTADOS** ⚠️
**Severidade:** MÉDIA

**Problema:**

Código usa WARNING e ERROR sem explicar quando escolher cada um:

```python
log_event("warning", "dns_resolve", status="not_found", ...)
log_event("error", "dns_resolve", status="error", ...)
```

**Quando usar cada nível?**

Não está documentado! Veja a tabela recomendada:

```markdown
## Níveis de Log - Quando Usar

| Nível | Uso | Exemplo | Alerta? |
|-------|-----|---------|---------|
| DEBUG | Desenvolvimento | `valor_x = 42` | Não |
| INFO | Eventos normais | `login realizado, cache hit` | Não |
| WARNING | Problema esperado | `DNS timeout, recurso não encontrado` | ⚠️ Talvez |
| ERROR | Problema inesperado | `erro interno, falha crítica` | 🔴 Sim |
| CRITICAL | Sistema parado | `banco de dados indisponível` | 🛑 Crítico |

REGRA DE OURO:
- Algo que o usuário CAUSOU (entrada inválida)?     → INFO ou WARNING
- Algo que DEVERIA funcionar mas falhou?             → ERROR
- Sem operação de negócio possível?                  → CRITICAL
```

---

### **5. DOCSTRING DO LOGGING.PY AUSENTE** ❌
**Severidade:** ALTA

**Problema:**

Arquivo `logging.py` não tem docstring no topo:

```python
import logging
import os
# ... imports ...

LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)sZ | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s"
```

**Aluno não sabe:**
- Para que serve este arquivo
- Como usá-lo
- Quais classes existem
- Como estender

**Recomendação:**

Adicionar docstring módulo profissional:

```python
"""
Sistema de Logging Estruturado - Backend

Fornece logging formatado com cores, rastreamento de requisição e
estrutura de eventos para análise e auditoria.

COMPONENTES PRINCIPAIS:
======================

1. UTCFormatter:
   Formata logs em UTC (timezone consistente).
   
2. ConsoleUTCFormatter:
   Adiciona cores ANSI para melhor leitura no console.
   - 🔍 DEBUG  (cyan)
   - ✅ INFO   (verde)
   - ⚠️  WARNING (amarelo)
   - ❌ ERROR  (vermelho)
   - 🛑 CRITICAL (magenta)

3. RequestIdFilter:
   Injeta request_id em cada log para rastreabilidade.
   Formato: req=<uuid-ou-dash>

4. RequestLoggerAdapter:
   Wrapper do logger que adiciona request_id automaticamente.

5. log_event():
   Função para logging estruturado (RECOMENDADO).
   Padrão: evento=<nome> campo1=valor1 campo2=valor2


USO BÁSICO:
===========

from backend.core.logging import log_event, logger

# Logging estruturado (PREFERIDO)
log_event("info", "calculo_completo", 
    tipo="ipv4",
    duracao_ms=145,
    resultado="sucesso"
)

# Logging simples (menos comum)
logger.warning("Algo incomum aconteceu")


VARIÁVEIS DE AMBIENTE:
======================

APP_LOG_LEVEL:
    DEBUG, INFO, WARNING, ERROR, CRITICAL
    Padrão: INFO
    
APP_LOG_COLOR:
    0 ou 1 (ativar cores)
    Padrão: 1 (ativado)

APP_LOG_FORCE_COLOR:
    Force colors mesmo fora do terminal
    Padrão: 1


EXEMPLOS DE EVENTOS ESTRUTURADOS:
==================================

# Sucesso
log_event("info", "dns_resolve", 
    status="ok",
    hostname="google.com",
    ip="142.251.41.14",
    elapsed_ms=234
)

# Timeout
log_event("warning", "dns_resolve",
    status="timeout",
    hostname="slow-server.com",
    timeout_s=5,
    elapsed_ms=5000
)

# Erro
log_event("error", "dns_resolve",
    status="error",
    hostname="invalid.tld",
    exc_info=True  # Inclui stack trace
)


PADRÃO DE CAMPOS:
=================

Todos os eventos devem ter:
- evento: (obrigatório) Nome do evento
- status: (quando aplicável) ok, erro, timeout, not_found
- elapsed_ms: (para operações demoradas)

Nunca logar:
- Senhas ou tokens
- Números de cartão
- Dados PII (exceto IP/hostname)
"""
```

---

### **6. FALTA DE EXEMPLO EDUCACIONAL DE HIERARQUIA** ❌
**Severidade:** MÉDIA

**Problema:**

Hierarquia de exceções não é documentada visualmente:

```python
class InfraestruturaError(RuntimeError):
    """Erro de infraestrutura/serviço interno."""

class DnsResolucaoError(InfraestruturaError):
    """Falha geral ao resolver DNS."""

class DnsResolucaoTimeoutError(DnsResolucaoError):
    """Timeout durante resolução DNS."""
```

**Aluno não entende:**
- Por que 3 níveis de DNS?
- Como catch apenas Timeout vs qualquer DNS error?
- Quando criar nova exceção vs usar existente?

**Recomendação:**

Documentar com diagramas e casos de uso:

```python
"""
HIERARQUIA DE EXCEÇÕES

                    Exception (built-in)
                         │
            ┌────────────┬┴┬──────────────┐
            │            │ │              │
        ValueError    RuntimeError  TypeError  ...
            │            │
            │            └─ InfraestruturaError (erros internos)
            │                 │
            │         ┌───────┼───────────────┐
            │         │       │               │
    EntradaInvalidaError  DnsResolucaoError HistoricoPersistenciaError
    (validação input)        │
                    (DNS falhou)
                        │
            DnsResolucaoTimeoutError
                    (DNS foi lento)


QUANDO USAR CADA UMA:
=====================

EntradaInvalidaError:
  Levante quando: Usuário forneceu dados inválidos
  Exemplo:
    def processar_ip(ip_str):
        if not validar_formato_ip(ip_str):
            raise EntradaInvalidaError(f"IP inválido: {ip_str}")
  
  Será capturada em: Validação de request


DnsResolucaoError:
  Levante quando: Problema ao resolver DNS
  Exemplos: domínio não existe, rede indisponível
  Exemplo:
    try:
        ip = socket.gethostbyname("invalid.tld")
    except socket.gaierror as e:
        raise DnsResolucaoError("Domínio não encontrado") from e


DnsResolucaoTimeoutError:
  Levante quando: DNS demorou demais
  Permite retry automático (ex: mudar servidor DNS)
  Exemplo:
    try:
        ip = socket.gethostbyname(hostname)
    except TimeoutError as e:
        raise DnsResolucaoTimeoutError("DNS timeout") from e


PADRÃO DE CAPTURA (try/except):
================================

# Capturar Timeout específico
try:
    ip = resolver_dns()
except DnsResolucaoTimeoutError:
    # Tentar servidor DNS alternativo
    ip = resolver_dns_backup()
except DnsResolucaoError:
    # Log e falha
    raise


# Capturar qualquer erro de DNS
try:
    ip = resolver_dns()
except DnsResolucaoError:  # Captura TimeoutError também!
    # Porque DnsResolucaoTimeoutError é subclasse
    log_event("warning", "dns_falhou")
    usar_cache()
"""
```

---

## 🔧 MELHORIAS RECOMENDADAS (PRIORITÁRIAS)

### **1️⃣ Documentar Exceções com Exemplos**
**Arquivo:** `backend/core/exceptions.py`
**Tempo:** 30 minutos
**Impacto:** CRÍTICO

```python
class EntradaInvalidaError(ValueError):
    """
    Erro de validação de entrada - informado ao usuário final.
    
    Levantada quando o usuário fornece dados inválidos.
    A mensagem será exibida diretamente na resposta HTTP.
    
    Características:
    - Não expõe detalhes técnicos
    - Mensagem curta e clara (< 100 caracteres)
    - Sempre causada por input do usuário
    
    Exemplo:
        def validar_cidr(cidr_str):
            try:
                partes = cidr_str.split('/')
                if len(partes) != 2:
                    raise EntradaInvalidaError("CIDR deve conter /")
            except ValueError:
                raise EntradaInvalidaError(f"CIDR inválido: {cidr_str}")
    
    Vs:
        InfraestruturaError: Para problemas internos (não causados pelo usuário)
    """

class InfraestruturaError(RuntimeError):
    """
    Erro de infraestrutura ou serviço interno.
    
    Levantada quando algo DEVERIA funcionar mas falhou.
    NÃO é causada por input do usuário.
    
    Características:
    - Pode ser retentada (pode ser transitório)
    - Registrada no log com detalhes técnicos (exc_info=True)
    - Exibe mensagem genérica ao usuário
    
    Exemplo (NÃO fazer):
        try:
            resultado = operacao_critica()
        except Exception:
            raise InfraestruturaError("Erro interno")  # Muito genérica!
    
    Exemplo (FAZER):
        try:
            resultado = operacao_critica()
        except ConnectionError as exc:
            log_event("error", "banco_indisponivel", exc_info=True)
            raise InfraestruturaError("Serviço temporariamente indisponível") from exc
    """

class DnsResolucaoError(InfraestruturaError):
    """
    Falha ao resolver DNS - domínio não existe ou rede indisponível.
    
    Subclasse de InfraestruturaError.
    
    Causas comuns:
    - Domínio não existe
    - Rede indisponível
    - Firewall bloqueando DNS
    
    Exemplo:
        try:
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as exc:
            log_event("warning", "dns_falhou", hostname=hostname)
            raise DnsResolucaoError(f"Não consegui resolver: {hostname}") from exc
    
    Vs:
        DnsResolucaoTimeoutError: Quando DNS demorou demais (pode retentar)
    """

class DnsResolucaoTimeoutError(DnsResolucaoError):
    """
    Timeout durante resolução DNS - servidor DNS não respondeu a tempo.
    
    Subclasse de DnsResolucaoError.
    Permite retry automático com outro servidor.
    
    Exemplo:
        try:
            ip = socket.gethostbyname(hostname)
        except TimeoutError as exc:
            log_event("warning", "dns_timeout", hostname=hostname)
            raise DnsResolucaoTimeoutError(f"DNS demorou demais: {hostname}") from exc
    
    Tratamento recomendado:
        try:
            ip = resolver_dns(hostname)
        except DnsResolucaoTimeoutError:
            # Retentar com servidor DNS alternativo
            ip = resolver_dns_alternativo(hostname)
    """

class HistoricoPersistenciaError(InfraestruturaError):
    """
    Falha ao carregar ou salvar histórico local.
    
    Causas comuns:
    - Disco cheio
    - Arquivo corrompido
    - Permissão insuficiente
    
    Exemplo:
        try:
            historico = carregar_historico_local()
        except (IOError, json.JSONDecodeError) as exc:
            log_event("error", "historico_leitura_falhou", exc_info=True)
            raise HistoricoPersistenciaError("Histórico indisponível") from exc
    """
```

---

### **2️⃣ Criar Guia de Logging Estruturado**
**Arquivo:** `backend/core/logging_guide.md` (NOVO)
**Tempo:** 45 minutos
**Impacto:** ALTO

```markdown
# Guia de Logging Estruturado

## Quick Start

```python
from backend.core.logging import log_event

# Evento bem-sucedido
log_event("info", "dns_resolve",
    status="ok",
    hostname="example.com",
    ip="93.184.216.34",
    elapsed_ms=145
)

# Evento com problema esperado
log_event("warning", "dns_resolve",
    status="not_found",
    hostname="inexistente.test",
    elapsed_ms=2000
)

# Evento com erro inesperado
log_event("error", "database_query",
    status="error",
    query="SELECT * FROM logs",
    exc_info=True  # Inclui stack trace!
)
```

## Padrão de Campos

Sempre use esses campos:

- `evento`: Nome do evento (obrigatório)
- `status`: ok, erro, timeout, not_found, start, end
- `elapsed_ms`: Duração em milissegundos (para operações demoradas)

Opcionais:
- `hostname`, `ip`, `path`: Dados da operação
- `erro`: Tipo de erro
- `exc_info=True`: Inclui exception trace

## Boas Práticas

1. **Sempre logar o status:**
   ```python
   log_event("info", "operacao", status="ok")
   log_event("warning", "operacao", status="timeout")
   ```

2. **Medir tempo de operações críticas:**
   ```python
   inicio = time.perf_counter()
   resultado = operacao_demorada()
   elapsed_ms = int((time.perf_counter() - inicio) * 1000)
   log_event("info", "operacao", elapsed_ms=elapsed_ms)
   ```

3. **Logar erros com contexto:**
   ```python
   except Exception as e:
       log_event("error", "operacao",
           erro=type(e).__name__,
           mensagem=str(e)[:100],
           exc_info=True  # Adiciona stack trace
       )
   ```

4. **Nunca logar dados sensíveis:**
   ```python
   # ❌ ERRADO
   log_event("info", "login", password=senha)
   
   # ✅ CERTO
   log_event("info", "login", user_id=123, status="ok")
   ```

## Exemplo Completo

```python
def processar_usuario(usuario_id):
    log_event("info", "processar_usuario", 
        status="start",
        usuario_id=usuario_id
    )
    
    inicio = time.perf_counter()
    
    try:
        usuario = carregar_usuario(usuario_id)
        log_event("info", "usuario_carregado",
            usuario_id=usuario_id,
            elapsed_ms=int((time.perf_counter() - inicio) * 1000)
        )
        
    except UsuarioNaoEncontradoError as e:
        log_event("warning", "processar_usuario",
            status="not_found",
            usuario_id=usuario_id,
            elapsed_ms=int((time.perf_counter() - inicio) * 1000)
        )
        raise EntradaInvalidaError(f"Usuário {usuario_id} não encontrado") from e
        
    except Exception as e:
        log_event("error", "processar_usuario",
            status="erro",
            usuario_id=usuario_id,
            erro=type(e).__name__,
            exc_info=True
        )
        raise InfraestruturaError("Erro ao processar usuário") from e
```
```

---

### **3️⃣ Criar Padrão de Try/Except Educacional**
**Arquivo:** `backend/core/exception_patterns.py` (NOVO)
**Tempo:** 1 hora
**Impacto:** MUITO ALTO

Veja documento separado: `PADROES_EXCECOES.md`

---

## 📚 DOCUMENTAÇÃO PENDENTE

| Documento | Conteúdo | Prioridade |
|-----------|----------|-----------|
| `exceptions_guide.md` | Quando usar cada exceção | 🔴 CRÍTICA |
| `logging_guide.md` | Como fazer logging estruturado | 🔴 CRÍTICA |
| `exception_patterns.py` | Padrões de tratamento com exemplos | 🟡 ALTA |
| Docstring em `logging.py` | Explicar arquivo principal | 🟡 ALTA |
| Docstring em `exceptions.py` | Documentar cada exceção | 🟡 ALTA |

---

## 🎯 CHECKLIST DE IMPLEMENTAÇÃO

```
FASE 1 - DOCUMENTAÇÃO (Semana 1):
□ Expandir docstrings em exceptions.py
□ Adicionar docstring em logging.py
□ Criar exceptions_guide.md
□ Criar logging_guide.md

FASE 2 - PADRÕES (Semana 2):
□ Criar exception_patterns.py com 10 exemplos
□ Comentar cada padrão
□ Incluir anti-patterns (o que NÃO fazer)

FASE 3 - REFATORAÇÃO (Semana 3-4):
□ Padronizar todos os try/except do código
□ Substituir logger.warning() por log_event()
□ Adicionar métricas de tempo quando aplicável

FASE 4 - EDUCAÇÃO (Contínuo):
□ Incluir exemplos nos testes
□ Criar slides educacionais
□ Documentar em README.md
```

---

## 📊 IMPACTO DAS MELHORIAS

| Melhoria | Impacto | Tempo |
|----------|---------|-------|
| Documentar exceções | Alunos entendem quando usá-las | 30 min |
| Padronizar logging | Código consistente | 2h |
| Exemplos comentados | Aprendizado prático | 3h |
| Padrões de try/except | Reduz erros comuns | 2h |

**Total:** ~7.5 horas para transformar em material educacional profissional

---

**Próximos Passos:**
1. Implementar Fase 1 (documentação)
2. Revisar com alunos
3. Refatorar código conforme padrões
4. Incorporar em currículo
