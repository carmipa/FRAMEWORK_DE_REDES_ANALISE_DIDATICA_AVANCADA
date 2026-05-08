"""Padrões educacionais de tratamento de exceções.

Este módulo não é parte do runtime principal. Ele documenta snippets
reutilizáveis para validação, fallback e tratamento de erros inesperados.
"""

from __future__ import annotations

import ipaddress
from typing import Callable, TypeVar

from backend.core.exceptions import (
    EntradaInvalidaError,
    InfraestruturaError,
)
from backend.core.logging import log_event

T = TypeVar("T")


def validar_cidr_usuario(cidr: str) -> str:
    """Padrão 1: erro de entrada do usuário."""
    raw = (cidr or "").strip()
    if not raw:
        log_event("warning", "cidr_validate", status="empty")
        raise EntradaInvalidaError("CIDR não pode estar vazio.")
    try:
        ipaddress.ip_network(raw, strict=False)
    except ValueError as exc:
        log_event("warning", "cidr_validate", status="invalid", cidr=raw)
        raise EntradaInvalidaError(f"CIDR inválido: {raw}") from exc
    return raw


def executar_com_fallback(
    preferencial: Callable[[], T],
    fallback: Callable[[], T],
    evento: str,
) -> T:
    """Padrão 2: erro esperado com fallback."""
    try:
        result = preferencial()
        log_event("info", evento, status="ok", source="preferencial")
        return result
    except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        log_event(
            "warning",
            evento,
            status="fallback",
            erro=type(exc).__name__,
        )
        try:
            result = fallback()
            log_event("info", evento, status="ok", source="fallback")
            return result
        except Exception as fallback_exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            log_event(
                "error",
                evento,
                status="error",
                erro=type(fallback_exc).__name__,
                exc_info=True,
            )
            raise InfraestruturaError("Falha na operação principal e no fallback.") from fallback_exc


def encapsular_erro_interno(evento: str, op: Callable[[], T]) -> T:
    """Padrão 3: erro inesperado com encapsulamento seguro."""
    try:
        return op()
    except EntradaInvalidaError:
        raise
    except Exception as exc:  # noqa: BLE001  # pylint: disable=broad-exception-caught
        log_event("error", evento, status="error", erro=type(exc).__name__, exc_info=True)
        raise InfraestruturaError("Erro interno ao processar solicitação.") from exc
