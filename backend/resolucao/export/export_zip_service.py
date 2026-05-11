"""Geração do pacote ZIP do laboratório Packet Tracer."""

from io import BytesIO
import zipfile

from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event
from backend.resolucao.export.export_txt_service import (
    generate_packet_tracer_script,
    generate_router_lab_blocks,
    router_export_filename,
)


def generate_packet_tracer_zip_buffer(scenario):
    if not scenario:
        log_event("warning", "problem_export_zip", status="empty_scenario")
        raise EntradaInvalidaError("Cenário vazio para exportação.")
    lan_blocks = scenario.get("lan_blocks") or []
    if not lan_blocks:
        log_event("warning", "problem_export_zip", status="empty_locations")
        raise EntradaInvalidaError(
            "Não há localidades no cenário para exportação."
        )

    consolidated_script = generate_packet_tracer_script(scenario)
    router_blocks = generate_router_lab_blocks(scenario)
    topology_mermaid = scenario.get("topology_mermaid", "")
    try:
        as_num = int(scenario.get("eigrp_as") or 71)
    except (TypeError, ValueError):
        as_num = 71
    readme = (
        "INSTRUCOES DE USO DO LABORATORIO\n"
        "===============================\n"
        "1. Abra o Cisco Packet Tracer.\n"
        "2. Monte a topologia física conforme o arquivo "
        "LAB_TOPOLOGY.mermaid.\n"
        "3. Para cada roteador, abra o CLI e cole o conteúdo do arquivo "
        "em configs_individuais/.\n"
        f"4. Aguarde a convergência do EIGRP (AS {as_num}; tipicamente alguns segundos).\n"
        "5. Em cada LAN, use pelo menos 2 PCs no switch para testar ping entre todas as localidades.\n"
        "6. Valide com: show ip interface brief, show ip eigrp neighbors "
        "e show ip route eigrp.\n"
    )

    memory_file = BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config_packet_tracer_consolidado.txt", consolidated_script)
        for location_name, block in router_blocks.items():
            filename = router_export_filename(location_name)
            zf.writestr(f"configs_individuais/{filename}", block + "\n")
        zf.writestr("LAB_TOPOLOGY.mermaid", topology_mermaid)
        zf.writestr("README_LAB.txt", readme)

    memory_file.seek(0)
    log_event(
        "info",
        "problem_export_zip",
        status="ok",
        routers_count=len(lan_blocks),
        files_written=len(router_blocks) + 3,
    )
    return memory_file
