"""
Tabela de referência de máscaras de subrede.
Converte entre prefix CIDR, máscara decimal, número de hosts e uso típico.
"""

MASCARA_REFERENCE_TABLE = [
    {"prefix": 8, "mask": "255.0.0.0", "hosts": 16_777_214, "binary": "11111111.00000000.00000000.00000000", "class": "A", "usage": "Rede Classe A"},
    {"prefix": 9, "mask": "255.128.0.0", "hosts": 8_388_606, "binary": "11111111.10000000.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 10, "mask": "255.192.0.0", "hosts": 4_194_302, "binary": "11111111.11000000.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 11, "mask": "255.224.0.0", "hosts": 2_097_150, "binary": "11111111.11100000.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 12, "mask": "255.240.0.0", "hosts": 1_048_574, "binary": "11111111.11110000.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 13, "mask": "255.248.0.0", "hosts": 524_286, "binary": "11111111.11111000.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 14, "mask": "255.252.0.0", "hosts": 262_142, "binary": "11111111.11111100.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 15, "mask": "255.254.0.0", "hosts": 131_070, "binary": "11111111.11111110.00000000.00000000", "class": "A", "usage": "Subrede A"},
    {"prefix": 16, "mask": "255.255.0.0", "hosts": 65_534, "binary": "11111111.11111111.00000000.00000000", "class": "B", "usage": "Rede Classe B"},
    {"prefix": 17, "mask": "255.255.128.0", "hosts": 32_766, "binary": "11111111.11111111.10000000.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 18, "mask": "255.255.192.0", "hosts": 16_382, "binary": "11111111.11111111.11000000.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 19, "mask": "255.255.224.0", "hosts": 8_190, "binary": "11111111.11111111.11100000.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 20, "mask": "255.255.240.0", "hosts": 4_094, "binary": "11111111.11111111.11110000.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 21, "mask": "255.255.248.0", "hosts": 2_046, "binary": "11111111.11111111.11111000.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 22, "mask": "255.255.252.0", "hosts": 1_022, "binary": "11111111.11111111.11111100.00000000", "class": "B", "usage": "Subrede B"},
    {"prefix": 23, "mask": "255.255.254.0", "hosts": 510, "binary": "11111111.11111111.11111110.00000000", "class": "B", "usage": "Subrede B (2x /24)"},
    {"prefix": 24, "mask": "255.255.255.0", "hosts": 254, "binary": "11111111.11111111.11111111.00000000", "class": "C", "usage": "Rede Classe C"},
    {"prefix": 25, "mask": "255.255.255.128", "hosts": 126, "binary": "11111111.11111111.11111111.10000000", "class": "C", "usage": "Subrede C"},
    {"prefix": 26, "mask": "255.255.255.192", "hosts": 62, "binary": "11111111.11111111.11111111.11000000", "class": "C", "usage": "Subrede C"},
    {"prefix": 27, "mask": "255.255.255.224", "hosts": 30, "binary": "11111111.11111111.11111111.11100000", "class": "C", "usage": "Pequena LAN"},
    {"prefix": 28, "mask": "255.255.255.240", "hosts": 14, "binary": "11111111.11111111.11111111.11110000", "class": "C", "usage": "Pequena LAN"},
    {"prefix": 29, "mask": "255.255.255.248", "hosts": 6, "binary": "11111111.11111111.11111111.11111000", "class": "C", "usage": "Muito pequena"},
    {"prefix": 30, "mask": "255.255.255.252", "hosts": 2, "binary": "11111111.11111111.11111111.11111100", "class": "WAN", "usage": "Link WAN (router-router)"},
    {"prefix": 31, "mask": "255.255.255.254", "hosts": 2, "binary": "11111111.11111111.11111111.11111110", "class": "P2P", "usage": "Point-to-Point (RFC 3021)"},
    {"prefix": 32, "mask": "255.255.255.255", "hosts": 1, "binary": "11111111.11111111.11111111.11111111", "class": "Host", "usage": "Host único"},
]


def get_reference_table():
    """Retorna tabela completa de máscaras para frontend"""
    return MASCARA_REFERENCE_TABLE


def lookup_by_prefix(prefix: int):
    """Lookup rápido por prefix CIDR"""
    for entry in MASCARA_REFERENCE_TABLE:
        if entry["prefix"] == prefix:
            return entry
    return None


def lookup_by_mask(mask: str):
    """Lookup rápido por máscara decimal"""
    for entry in MASCARA_REFERENCE_TABLE:
        if entry["mask"] == mask:
            return entry
    return None


def lookup_by_hosts(host_count: int):
    """Encontra o menor prefix que comporta o número de hosts"""
    for entry in sorted(MASCARA_REFERENCE_TABLE, key=lambda x: x["hosts"], reverse=True):
        if entry["hosts"] >= host_count:
            return entry
    return None
