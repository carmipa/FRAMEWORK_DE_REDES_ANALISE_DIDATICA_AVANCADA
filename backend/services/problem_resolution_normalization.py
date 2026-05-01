from backend.common import EntradaInvalidaError


DEFAULT_LOCATIONS = [
    {"name": "Matriz", "hosts": 420},
    {"name": "Filial I", "hosts": 400},
    {"name": "Filial II", "hosts": 380},
]


def parse_positive_int(value, field_label):
    txt = (value or "").strip()
    if not txt:
        raise EntradaInvalidaError(f"{field_label} deve ser informado.")
    if not txt.isdigit():
        raise EntradaInvalidaError(f"{field_label} deve ser um número inteiro positivo.")
    number = int(txt)
    if number <= 0:
        raise EntradaInvalidaError(f"{field_label} deve ser maior que zero.")
    return number


def normalize_cli_identifier(value, fallback="SITE"):
    txt = (value or "").strip().upper()
    clean = "".join(ch if ch.isalnum() else "_" for ch in txt)
    clean = "_".join(part for part in clean.split("_") if part)
    return clean or fallback


def normalize_locations_input(locations_input):
    normalized = []
    for index, raw in enumerate(locations_input, start=1):
        name = (raw.get("name") or "").strip()
        if not name:
            raise EntradaInvalidaError(f"Nome da localidade #{index} deve ser informado.")
        hosts = parse_positive_int(raw.get("hosts"), f"Hosts de {name}")
        normalized.append(
            {
                "location_key": f"loc_{index}",
                "location_name": name,
                "hosts_required": hosts,
                "router_name": f"R-{normalize_cli_identifier(name, f'SITE{index}')}",
                "cli_id": normalize_cli_identifier(name, f"SITE{index}"),
            }
        )
    if not normalized:
        raise EntradaInvalidaError("Informe ao menos uma localidade.")
    return normalized
