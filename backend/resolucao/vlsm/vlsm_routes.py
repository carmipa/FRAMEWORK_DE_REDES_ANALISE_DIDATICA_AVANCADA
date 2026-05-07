from flask import Blueprint, current_app, render_template, request, send_file

from backend.analise.cidr_service import inferir_cidr_por_ip
from backend.core.exceptions import EntradaInvalidaError
from backend.core.logging import log_event
from backend.resolucao.vlsm.vlsm_service import (
    DEFAULT_LOCATIONS,
    generate_entrega_relatorio_txt,
    generate_packet_tracer_script,
    generate_packet_tracer_zip_buffer,
    solve_network_problem,
)

resolucao_bp = Blueprint("resolucao", __name__)


@resolucao_bp.route("/resolucao-problemas", methods=["GET", "POST"])
def resolucao_problemas():
    erro = None
    invalid_fields = set()
    form_data = {
        "base_network": "172.21.0.0/16",
        "base_network_ip": "172.21.0.0",
        "base_network_cidr": "16",
        "topology_type": "ring",
        "wan_prefix": "30",
    }
    locations = [dict(item) for item in DEFAULT_LOCATIONS]
    scenario = None

    if request.method == "POST":
        action_type = request.form.get("action_type", "calculate").strip().lower()
        base_network_raw = request.form.get("base_network", "").strip()
        base_network_ip = request.form.get("base_network_ip", "").strip()
        base_network_cidr = request.form.get("base_network_cidr", "").strip()
        wan_prefix = request.form.get("wan_prefix", "30").strip() or "30"
        if base_network_ip and not base_network_cidr:
            try:
                inferred_cidr, _ = inferir_cidr_por_ip(base_network_ip)
                base_network_cidr = str(inferred_cidr)
            except EntradaInvalidaError:
                pass
        if base_network_ip and base_network_cidr:
            base_network_value = f"{base_network_ip}/{base_network_cidr}"
        elif base_network_raw:
            base_network_value = base_network_raw
        else:
            base_network_value = ""
        form_data = {
            "base_network": base_network_value,
            "base_network_ip": base_network_ip,
            "base_network_cidr": base_network_cidr,
            "topology_type": request.form.get("topology_type", "ring").strip().lower()
            or "ring",
            "wan_prefix": wan_prefix,
        }
        if form_data["base_network"] and (
            not form_data["base_network_ip"] or not form_data["base_network_cidr"]
        ):
            if "/" in form_data["base_network"]:
                ip_part, cidr_part = form_data["base_network"].split("/", 1)
                form_data["base_network_ip"] = (
                    form_data["base_network_ip"] or ip_part.strip()
                )
                form_data["base_network_cidr"] = (
                    form_data["base_network_cidr"] or cidr_part.strip()
                )
        location_names = request.form.getlist("loc_name")
        location_hosts = request.form.getlist("loc_hosts")
        locations = []
        total_rows = max(len(location_names), len(location_hosts))
        for index in range(total_rows):
            name = location_names[index].strip() if index < len(location_names) else ""
            hosts = location_hosts[index].strip() if index < len(location_hosts) else ""
            if not name and not hosts:
                continue
            locations.append({"name": name, "hosts": hosts})
        log_event(
            "info",
            "problem_resolution_use",
            action_type=action_type,
            locations_count=len(locations),
            topology_type=form_data["topology_type"],
            reason="Usuário executou resolução de cenário VLSM/WAN para estudo ou laboratório.",
        )

        try:
            scenario = solve_network_problem(
                form_data["base_network"],
                locations,
                topology_type=form_data["topology_type"],
                wan_prefix=form_data["wan_prefix"],
            )
            if action_type == "export":
                log_event(
                    "info",
                    "problem_resolution_export",
                    export_type="txt",
                    reason="Usuário exportou script consolidado para aplicar no Packet Tracer.",
                )
                content = generate_packet_tracer_script(scenario)
                filename = "config_packet_tracer_consolidado.txt"
                return current_app.response_class(
                    content,
                    mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                )
            if action_type == "export_zip":
                log_event(
                    "info",
                    "problem_resolution_export",
                    export_type="zip",
                    reason="Usuário exportou pacote ZIP com configs para laboratório.",
                )
                zip_file = generate_packet_tracer_zip_buffer(scenario)
                return send_file(
                    zip_file,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name="laboratorio_packet_tracer.zip",
                )
            if action_type == "export_entrega":
                log_event(
                    "info",
                    "problem_resolution_export",
                    export_type="entrega_txt",
                    reason="Usuário exportou relatório completo da tela para entrega.",
                )
                content = generate_entrega_relatorio_txt(scenario)
                filename = "documentacao_cenario_rede.txt"
                return current_app.response_class(
                    content,
                    mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                )
        except EntradaInvalidaError as exc:
            erro = str(exc)
            if not form_data["base_network"]:
                invalid_fields.add("base_network")
            if not locations:
                invalid_fields.add("loc_hosts")
            if form_data["topology_type"] not in {"ring", "mesh"}:
                invalid_fields.add("topology_type")
            try:
                wan_prefix_i = int(form_data["wan_prefix"])
                if wan_prefix_i < 0 or wan_prefix_i > 30:
                    invalid_fields.add("wan_prefix")
            except (TypeError, ValueError):
                invalid_fields.add("wan_prefix")
        except Exception as exc:
            log_event(
                "error",
                "problem_resolution_use",
                status="error",
                action_type=action_type,
                erro=exc.__class__.__name__,
                exc_info=True,
            )
            erro = "Erro interno ao processar a resolução de problemas. Tente novamente."

    return render_template(
        "resolucao/resolucao_problemas.html",
        active_main_menu="resolucao",
        erro=erro,
        invalid_fields=invalid_fields,
        form_data=form_data,
        locations=locations,
        scenario=scenario,
    )
