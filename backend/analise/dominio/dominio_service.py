"""Modo domínio — resolução DNS e inferência de CIDR."""

from backend.analise.cidr_service import inferir_cidr_por_ip
from backend.analise.dominio_service import resolver_dns_com_cache
from backend.analise.helpers_web import normalizar_hostname_entrada
from backend.core.exceptions import DnsResolucaoError
from backend.core.logging import log_event, logger


def processar_modo_dominio(ip_entrada_bruta: str, cidr_raw: str) -> dict:
    invalid_fields: set[str] = set()
    erro = None
    ip_p = ""
    cidr_val = None
    cidr_origem = ""

    dominio_digitado = normalizar_hostname_entrada(ip_entrada_bruta)
    if not dominio_digitado:
        erro = (
            "No modo Decompor Domínio para IP, informe um domínio/hostname "
            "(ex.: google.com)."
        )
        invalid_fields.add("ip")
    elif (
        "." not in dominio_digitado
        and not dominio_digitado.replace("-", "").isalnum()
    ):
        erro = (
            "Domínio/hostname inválido. Use algo como google.com ou "
            "servidor.local."
        )
        invalid_fields.add("ip")
    else:
        try:
            log_event("info", "calc", status="start", modo="dominio")
            ip_p = resolver_dns_com_cache(dominio_digitado)
            if cidr_raw:
                cidr_val = int(cidr_raw)
                cidr_origem = (
                    f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                    "CIDR informado manualmente."
                )
            else:
                cidr_val, origem_inferida = inferir_cidr_por_ip(ip_p)
                cidr_origem = (
                    f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                    f"{origem_inferida}."
                )
        except ValueError:
            logger.warning(
                "evento=calc status=invalid_input modo=dominio campo=cidr"
            )
            erro = (
                "No modo Domínio, o CIDR (se informado) deve ser um número "
                "inteiro entre 0 e 32."
            )
            invalid_fields.add("cidr")
        except DnsResolucaoError as exc:
            logger.warning(
                "evento=calc status=dns_error modo=dominio erro=%s", exc
            )
            erro = str(exc)
            invalid_fields.add("ip")

    return {
        "erro": erro,
        "ip_p": ip_p,
        "cidr_val": cidr_val,
        "cidr_origem": cidr_origem,
        "invalid_fields": invalid_fields,
    }
