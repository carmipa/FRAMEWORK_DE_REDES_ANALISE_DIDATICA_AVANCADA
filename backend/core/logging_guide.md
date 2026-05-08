# Guia de Logging Estruturado

## Objetivo

Padronizar logs do backend para facilitar:

- leitura humana no terminal;
- rastreabilidade por `request_id`;
- auditoria de eventos;
- troubleshooting de produção.

## Uso recomendado

Sempre preferir `log_event()`:

```python
from backend.core.logging import log_event

log_event(
    "info",
    "dns_resolve",
    status="ok",
    hostname="example.com",
    ip="93.184.216.34",
    elapsed_ms=120,
)
```

## Níveis de log

- `debug`: detalhes de desenvolvimento.
- `info`: fluxo normal da aplicação.
- `warning`: condição esperada com impacto parcial.
- `error`: falha inesperada (usar `exc_info=True` quando aplicável).
- `critical`: indisponibilidade severa.

## Campos recomendados

- `status`: `start`, `ok`, `warning`, `error`, `timeout`, `not_found`.
- `elapsed_ms`: duração de operações relevantes.
- contexto mínimo da operação (`path`, `hostname`, `modo`, `code`, etc.).

## Boas práticas

- não registrar segredos (tokens, senhas, credenciais);
- preferir eventos curtos e sem texto livre excessivo;
- manter nomes de evento estáveis para facilitar filtros.
