from backend.analise.protocolos.protocolos_catalog import PROTOCOLOS_CATALOGO


def filtrar_protocolos(query: str) -> list:
    q = query.strip().lower()
    if not q:
        return PROTOCOLOS_CATALOGO
    return [p for p in PROTOCOLOS_CATALOGO if q in p.get('nome', '').lower() or q in p.get('funcao', '').lower()]


def agrupar_por_camada() -> dict:
    grupos = {}
    for p in PROTOCOLOS_CATALOGO:
        camada = p.get('camada', 'Outros')
        grupos.setdefault(camada, []).append(p)
    return grupos
