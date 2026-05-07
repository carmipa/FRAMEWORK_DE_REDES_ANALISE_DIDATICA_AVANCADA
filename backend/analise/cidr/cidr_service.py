from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import logger
from backend.analise.cidr_service import inferir_cidr_por_ip


def processar_modo_cidr(ip_p: str, cidr_raw: str) -> dict:
    invalid_fields = set()
    cidr_val = None
    cidr_origem = ""
    erro = None

    if cidr_raw:
        try:
            cidr_val = int(cidr_raw)
        except ValueError:
            logger.warning("evento=calc status=invalid_input modo=cidr campo=cidr")
            erro = "O CIDR deve ser um número inteiro entre 0 e 32."
            invalid_fields.add("cidr")
    elif ip_p:
        try:
            cidr_val, origem_inferida = inferir_cidr_por_ip(ip_p)
            cidr_origem = (
                "Campo CIDR vazio — prefixo (/barra) inferido pelo 1º octeto do IP "
                "(modelo classful didático). "
                f"{origem_inferida}"
            )
        except EntradaInvalidaError as exc:
            logger.warning("evento=calc status=invalid_input modo=cidr campo=ip erro=%s", exc)
            erro = str(exc)
            invalid_fields.add("ip")
    else:
        erro = (
            "No modo CIDR, informe o endereço IPv4 e o CIDR (0–32), "
            "ou apenas o IPv4 para descobrir o / automaticamente pelo 1º octeto."
        )
        invalid_fields.add("cidr")
        invalid_fields.add("ip")

    return {
        "erro": erro,
        "cidr_val": cidr_val,
        "cidr_origem": cidr_origem,
        "invalid_fields": invalid_fields,
    }
