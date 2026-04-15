import logging
import os
import time
import uuid
import json
import io
import ipaddress
import webbrowser
import threading
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from collections import deque

from flask import Flask, g, request, render_template, jsonify, send_file, redirect, url_for
import socket
from werkzeug.exceptions import HTTPException

app = Flask(__name__)

# Logging estruturado para rastreabilidade (GRC/auditoria)
LOG_LEVEL = os.getenv("APP_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | req=%(request_id)s | %(message)s",
)
_base_logger = logging.getLogger("cybernet")


class RequestIdFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "request_id"):
            try:
                record.request_id = getattr(g, "request_id", "-")
            except RuntimeError:
                record.request_id = "-"
        return True


for handler in logging.getLogger().handlers:
    handler.addFilter(RequestIdFilter())


class RequestLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        extra = kwargs.setdefault("extra", {})
        try:
            request_id = getattr(g, "request_id", "-")
        except RuntimeError:
            request_id = "-"
        extra.setdefault("request_id", request_id)
        return msg, kwargs


logger = RequestLoggerAdapter(_base_logger, {})

BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "consulta_history.json"
MAX_HISTORY = 60
DNS_CACHE_TTL_SECONDS = int(os.getenv("DNS_CACHE_TTL_SECONDS", "180"))

_dns_cache = {}
_history = deque(maxlen=MAX_HISTORY)


class EntradaInvalidaError(ValueError):
    """Erro de validação de entrada informado ao usuário."""


def _utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def _carregar_historico():
    if not HISTORY_FILE.exists():
        return
    try:
        raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            for item in raw[-MAX_HISTORY:]:
                if isinstance(item, dict):
                    _history.append(item)
    except Exception:
        logger.exception("Falha ao carregar histórico local de consultas")


def _persistir_historico():
    try:
        HISTORY_FILE.write_text(
            json.dumps(list(_history), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        logger.exception("Falha ao persistir histórico local de consultas")


def _registrar_consulta(entrada, res):
    if not res:
        return
    registro = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": _utc_now_iso(),
        "modo": entrada.get("modo", ""),
        "ip_entrada": entrada.get("ip", ""),
        "cidr_entrada": entrada.get("cidr", ""),
        "mask_entrada": entrada.get("mask_decimal", ""),
        "wildcard_entrada": entrada.get("wildcard_mask", ""),
        "rede": res.get("rede", ""),
        "broadcast": res.get("broad", ""),
        "mask": res.get("mask", ""),
        "cidr": res.get("cidr", ""),
        "tema": res.get("nivel_tema", ""),
    }
    _history.appendleft(registro)
    _persistir_historico()


def _resolver_dns_com_cache(hostname):
    h = (hostname or "").strip().lower()
    if not h:
        raise EntradaInvalidaError("Domínio/hostname vazio.")
    now = time.time()
    cached = _dns_cache.get(h)
    if cached and cached["expires_at"] > now:
        logger.info("DNS cache hit para hostname=%s", h)
        return cached["ip"]
    logger.info("DNS cache miss para hostname=%s", h)
    ip = socket.gethostbyname(h)
    _dns_cache[h] = {"ip": ip, "expires_at": now + DNS_CACHE_TTL_SECONDS}
    return ip


def _classificar_ipv6(addr):
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_private:
        return "ULA/Privado"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_global:
        return "Global unicast"
    return "Outro/Reservado"


def _processar_ipv6(ipv6_s):
    raw = (ipv6_s or "").strip().strip('"').strip("'")
    if not raw:
        raise EntradaInvalidaError("IPv6 vazio.")

    # Suporte a zone index de link-local (ex.: fe80::1%eth0 / fe80::1%12)
    zone = ""
    base = raw
    if "%" in raw:
        base, zone = raw.split("%", 1)
        base = base.strip()
        zone = zone.strip()
        if not zone:
            raise EntradaInvalidaError("IPv6 com zone index inválido (sufixo após % está vazio).")

    try:
        addr = ipaddress.IPv6Address(base)
    except Exception as exc:
        raise EntradaInvalidaError(f"IPv6 inválido: {exc}") from exc

    bits = bin(int(addr))[2:].zfill(128)
    blocos_16 = [bits[i:i + 16] for i in range(0, 128, 16)]
    comprimido = addr.compressed + (f"%{zone}" if zone else "")
    return {
        "entrada": raw,
        "comprimido": comprimido,
        "expandido": addr.exploded,
        "tipo": _classificar_ipv6(addr),
        "prefixo_sugerido": "/64 (didático para LAN IPv6)",
        "blocos_16": blocos_16,
        "primeiros_64": ":".join(addr.exploded.split(":")[:4]),
        "ultimos_64": ":".join(addr.exploded.split(":")[4:]),
        "zone_index": zone or "—",
    }


def _grc_resumo(res):
    if not res or res.get("somente_mascara"):
        return []
    cidr = int(res.get("cidr", 0))
    total = int(res.get("total", 0))
    tipo = res.get("ip_tipo_privacidade", "N/A")
    risco = res.get("nivel_tema", "N/A")
    superficie = (
        "Alta" if total >= 65536 else
        "Média" if total >= 256 else
        "Baixa"
    )
    recomendacao = (
        "Segmentar sub-redes e aplicar ACL por zona."
        if cidr <= 16
        else "Manter hardening e revisão periódica de regras."
    )
    return [
        f"Risco atual: {risco} ({tipo}).",
        f"Superfície estimada: {superficie} ({total} IPs no bloco).",
        f"Recomendação objetiva: {recomendacao}",
    ]


def _gerar_pdf_simples(texto):
    """Gera PDF básico (1 página) sem dependências externas."""
    def _pdf_safe_text(s):
        # Base14 font + stream simples funciona melhor com ASCII limpo.
        # Assim evitamos problemas de acentuação entre viewers.
        normalized = unicodedata.normalize("NFKD", s)
        ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
        return ascii_only.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [
        _pdf_safe_text(ln)[:110]
        for ln in texto.splitlines()
    ]
    stream_lines = [
        "BT",
        "/F1 11 Tf",
        "14 TL",          # line height
        "72 800 Td",      # initial text position
    ]
    for ln in lines[:58]:
        stream_lines.append(f"({ln}) Tj")
        stream_lines.append("T*")  # move to next line using current leading
    stream_lines.append("ET")
    content = "\n".join(stream_lines).encode("latin-1", errors="replace")

    objs = []
    objs.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
    objs.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
    objs.append(b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n")
    objs.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
    objs.append(f"5 0 obj << /Length {len(content)} >> stream\n".encode("ascii") + content + b"\nendstream endobj\n")

    output = io.BytesIO()
    output.write(b"%PDF-1.4\n")
    xref = [0]
    for obj in objs:
        xref.append(output.tell())
        output.write(obj)
    xref_pos = output.tell()
    output.write(f"xref\n0 {len(xref)}\n".encode("ascii"))
    output.write(b"0000000000 65535 f \n")
    for pos in xref[1:]:
        output.write(f"{pos:010d} 00000 n \n".encode("ascii"))
    output.write(
        f"trailer << /Size {len(xref)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode("ascii")
    )
    output.seek(0)
    return output


_carregar_historico()


def _classe_ipv4_didatica(o1):
    """Classificação didática pelo 1º octeto (IPv4 classful); CIDR tornou isso só referência histórica."""
    if o1 == 0:
        return "Reservado", "(0.0.0.0/8 — não roteável na Internet)"
    if o1 == 127:
        return "Loopback", "(127.0.0.0/8)"
    if 1 <= o1 <= 126:
        return "A", "faixa clássica 1–126 no 1º octeto"
    if 128 <= o1 <= 191:
        return "B", "faixa clássica 128–191 no 1º octeto"
    if 192 <= o1 <= 223:
        return "C", "faixa clássica 192–223 no 1º octeto"
    if 224 <= o1 <= 239:
        return "D", "multicast (224–239)"
    if 240 <= o1 <= 255:
        return "E", "experimental / reservado (240–255)"
    return "—", ""


def _classe_variant_css(classe):
    """Slug estável para classes CSS do banner de destaque."""
    return {
        "A": "a",
        "B": "b",
        "C": "c",
        "D": "d",
        "E": "e",
        "Reservado": "reservado",
        "Loopback": "loopback",
        "—": "outros",
    }.get(classe, "outros")


def _privacidade_rfc1918(parts):
    """Identifica tipo de IP para cenários comuns de prova."""
    o1, o2 = parts[0], parts[1]
    if o1 == 127:
        return "Loopback", "Faixa 127.0.0.0/8 (localhost, teste local)"
    if o1 == 169 and o2 == 254:
        return "APIPA", "Faixa 169.254.0.0/16 (auto-configuração sem DHCP)"
    if o1 == 10:
        return "Privado (RFC 1918)", "Faixa privada 10.0.0.0 - 10.255.255.255"
    if o1 == 172 and 16 <= o2 <= 31:
        return "Privado (RFC 1918)", "Faixa privada 172.16.0.0 - 172.31.255.255"
    if o1 == 192 and o2 == 168:
        return "Privado (RFC 1918)", "Faixa privada 192.168.0.0 - 192.168.255.255"
    if 224 <= o1 <= 239:
        return "Multicast", "Faixa 224.0.0.0 - 239.255.255.255 (não host unicast)"
    if 240 <= o1 <= 255:
        return "Reservado/Experimental", "Faixa 240.0.0.0 - 255.255.255.255"
    return "Público", "Fora das faixas privadas/locais (roteável conforme políticas)"


def _fmt_ip(n):
    return f"{(n >> 24) & 255}.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}"


def _parse_ipv4_parts(ip_s, nome_campo="IP"):
    txt = (ip_s or "").strip()
    if not txt:
        raise EntradaInvalidaError(f"{nome_campo} vazio.")
    raw_parts = txt.split(".")
    if len(raw_parts) != 4:
        raise EntradaInvalidaError(f"{nome_campo} inválido. Use formato x.x.x.x.")
    parts = []
    for idx, raw in enumerate(raw_parts, start=1):
        raw = raw.strip()
        if raw == "":
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} está vazio.")
        if not raw.isdigit():
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} não é numérico.")
        octeto = int(raw)
        if not (0 <= octeto <= 255):
            raise EntradaInvalidaError(f"{nome_campo} inválido: octeto {idx} fora de 0-255.")
        parts.append(octeto)
    return parts


def _inferir_cidr_por_ip(ip_s):
    """
    Inferência didática (classful) para provas quando CIDR não é informado.
    Retorna (cidr, descricao_origem).
    """
    parts = _parse_ipv4_parts(ip_s, "IP")
    o1 = parts[0]
    if o1 == 0:
        return 8, "Inferido por classe: reservado 0.x.x.x => /8"
    if 1 <= o1 <= 126:
        return 8, "Inferido por classe A => /8"
    if o1 == 127:
        return 8, "Inferido por loopback 127.x.x.x => /8"
    if 128 <= o1 <= 191:
        return 16, "Inferido por classe B => /16"
    if 192 <= o1 <= 223:
        return 24, "Inferido por classe C => /24"
    if 224 <= o1 <= 239:
        return 4, "Inferido por classe D (multicast) => /4"
    return 4, "Inferido por classe E (experimental/reservado) => /4"


def mascara_dotted_para_cidr(mask_s):
    """Converte máscara IPv4 pontuada (bits de rede contíguos) em prefixo /0–/32."""
    try:
        parts = _parse_ipv4_parts(mask_s, "Máscara decimal")
    except EntradaInvalidaError:
        return None
    val = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    val &= 0xffffffff
    inv = (~val) & 0xffffffff
    if inv != 0 and (inv & (inv + 1)) != 0:
        return None
    return val.bit_count()


def wildcard_dotted_para_cidr(wild_s):
    """Converte wildcard pontuada para CIDR via máscara inversa."""
    try:
        parts = _parse_ipv4_parts(wild_s, "Wildcard mask")
    except EntradaInvalidaError:
        return None
    mask_equivalente = ".".join(str(255 - o) for o in parts)
    return mascara_dotted_para_cidr(mask_equivalente)


def _core_mascara(cidr):
    """Dados derivados só do CIDR (máscara, bitmap, capacidade, pulo)."""
    if not isinstance(cidr, int) or not (0 <= cidr <= 32):
        return None
    m_i = (0xffffffff << (32 - cidr)) & 0xffffffff
    fmt = _fmt_ip
    if cidr >= 24:
        pulo = 2 ** (32 - cidr)
    elif cidr >= 16:
        pulo = 2 ** (24 - cidr)
    else:
        pulo = 2 ** (16 - cidr)

    tamanho = 2 ** (32 - cidr)
    if cidr == 32:
        uteis = 1
    elif cidr == 31:
        uteis = 2
    elif tamanho > 2:
        uteis = tamanho - 2
    else:
        uteis = 0

    return {
        "mask": fmt(m_i),
        "wildcard": fmt((~m_i) & 0xffffffff),
        "bin_raw": bin(m_i)[2:].zfill(32),
        "zeros": 32 - cidr,
        "total": tamanho,
        "uteis": uteis,
        "pulo": pulo,
        "cidr": cidr,
        "_m_i": m_i,
    }


def _tema_dinamico(cidr, total_ips):
    """
    Define paleta dinâmica para tabelas com base no prefixo e tamanho da rede.
    Quanto maior a rede (CIDR menor), mais quente o alerta visual.
    """
    if cidr >= 24:
        return {
            "cor_bit1": "#238636",
            "cor_resultado_and": "#3fb950",
            "cor_pulo": "#2ea043",
            "cor_borda_resumo": "#2ea043",
            "cor_acento": "#3fb950",
            "cor_borda_tabela": "#2d6a4f",
            "cor_cabecalho_tabela_bg": "#14261c",
            "cor_cabecalho_tabela_texto": "#8be9a8",
            "cor_linha_destaque": "rgba(63, 185, 80, 0.16)",
            "nivel_tema": "Baixo risco operacional",
            "nivel_tema_descricao": "Prefixo mais específico: bloco menor, varredura e governança mais simples.",
        }
    if cidr >= 17:
        return {
            "cor_bit1": "#1f6feb",
            "cor_resultado_and": "#79c0ff",
            "cor_pulo": "#58a6ff",
            "cor_borda_resumo": "#1f6feb",
            "cor_acento": "#79c0ff",
            "cor_borda_tabela": "#1f4f87",
            "cor_cabecalho_tabela_bg": "#101c2f",
            "cor_cabecalho_tabela_texto": "#9fd0ff",
            "cor_linha_destaque": "rgba(121, 192, 255, 0.16)",
            "nivel_tema": "Risco moderado",
            "nivel_tema_descricao": "Rede intermediária: atenção à segmentação e aos controles de acesso.",
        }
    if cidr >= 9:
        return {
            "cor_bit1": "#d29922",
            "cor_resultado_and": "#e3b341",
            "cor_pulo": "#f2cc60",
            "cor_borda_resumo": "#d29922",
            "cor_acento": "#e3b341",
            "cor_borda_tabela": "#7a611f",
            "cor_cabecalho_tabela_bg": "#2b2310",
            "cor_cabecalho_tabela_texto": "#f2d487",
            "cor_linha_destaque": "rgba(227, 179, 65, 0.16)",
            "nivel_tema": "Risco elevado",
            "nivel_tema_descricao": "Bloco amplo: recomenda-se dividir sub-redes e restringir superfície.",
        }
    return {
        "cor_bit1": "#f85149",
        "cor_resultado_and": "#ff7b72",
        "cor_pulo": "#ff7b72",
        "cor_borda_resumo": "#f85149",
        "cor_acento": "#ff7b72",
        "cor_borda_tabela": "#8b2f2a",
        "cor_cabecalho_tabela_bg": "#2f1414",
        "cor_cabecalho_tabela_texto": "#ffb3ad",
        "cor_linha_destaque": "rgba(248, 81, 73, 0.18)",
        "nivel_tema": "Risco crítico",
        "nivel_tema_descricao": "Rede muito extensa: alto impacto operacional e maior exposição para varredura.",
    }


def _tabela_referencia_subredes(cidr):
    """
    Gera tabela de referência dinâmica para o octeto relevante do CIDR.
    Ex.: /20 => octeto 3 => linhas /17 a /23.
    """
    if not isinstance(cidr, int) or not (0 <= cidr <= 32):
        return 4, []

    if cidr <= 8:
        octeto = 1
    elif cidr <= 16:
        octeto = 2
    elif cidr <= 24:
        octeto = 3
    else:
        octeto = 4

    start = (octeto - 1) * 8 + 1
    end = octeto * 8
    pesos = [128, 64, 32, 16, 8, 4, 2, 1]
    rows = []

    for barra in range(start, end + 1):
        bits_on = barra - ((octeto - 1) * 8)
        bits = [1 if i < bits_on else 0 for i in range(8)]
        mascara_octeto = sum(pesos[i] for i in range(bits_on))
        rows.append(
            {
                "barra": barra,
                "bits": bits,
                "intervalos": 2 ** bits_on,
                "variacao": 2 ** (8 - bits_on),
                "ips": 2 ** (32 - barra),
                "mascara_octeto": mascara_octeto,
                "is_current": barra == cidr,
            }
        )
    return octeto, rows


def _tabela_conversao_bits(cidr):
    """Tabela de estudo precisa para conversão entre bits e bytes."""
    linhas = [
        {"referencia": "1 bit", "bits": "1", "bytes": "0.125", "binario": "1", "decimal": "1"},
        {"referencia": "1 nibble", "bits": "4", "bytes": "0.5", "binario": "1111", "decimal": "15"},
        {"referencia": "1 byte (octeto)", "bits": "8", "bytes": "1", "binario": "11111111", "decimal": "255"},
        {
            "referencia": "1 word",
            "bits": "16",
            "bytes": "2",
            "binario": "11111111 11111111",
            "decimal": "65535",
        },
        {
            "referencia": "1 dword (IPv4)",
            "bits": "32",
            "bytes": "4",
            "binario": "32 bits em 1",
            "decimal": "4294967295",
        },
        {"referencia": "1 KiB", "bits": "8192", "bytes": "1024", "binario": "2^10 bytes", "decimal": "1024"},
        {"referencia": "1 MiB", "bits": "8388608", "bytes": "1048576", "binario": "2^20 bytes", "decimal": "1048576"},
    ]

    host_bits = 32 - cidr
    rede_bits = cidr
    conversao_atual = [
        {"chave": "Bits de rede", "valor": rede_bits},
        {"chave": "Bits de host", "valor": host_bits},
        {"chave": "Bits totais IPv4", "valor": 32},
        {"chave": "Bytes totais IPv4", "valor": "4"},
        {"chave": "Capacidade do bloco", "valor": f"2^{host_bits} = {2 ** host_bits} IPs"},
        {"chave": "Conversão útil", "valor": "1 byte = 8 bits | 1 nibble = 4 bits"},
    ]
    return linhas, conversao_atual


def processar_somente_mascara(cidr):
    """Exercício com máscara/CIDR sem endereço IP: sem rede/broadcast/hosts específicos."""
    c = _core_mascara(cidr)
    if c is None:
        return None
    out = {k: v for k, v in c.items() if k != "_m_i"}
    octeto_ref, tabela_ref = _tabela_referencia_subredes(cidr)
    tabela_conv, conv_atual = _tabela_conversao_bits(cidr)
    tema = _tema_dinamico(cidr, c["total"])
    out["somente_mascara"] = True
    out["cidr_origem"] = ""
    out["octeto_referencia"] = octeto_ref
    out["tabela_referencia"] = tabela_ref
    out["tabela_conversao_bits"] = tabela_conv
    out["conversao_atual"] = conv_atual
    out.update(tema)
    out["rede"] = out["broad"] = out["primeiro_host"] = out["ultimo_host"] = "—"
    return out


def _hosts_da_subrede(rede_i, broad_i, cidr):
    """Retorna primeiro e último host conforme regra do prefixo."""
    if cidr == 32:
        host = _fmt_ip(rede_i)
        return host, host
    if cidr == 31:
        return _fmt_ip(rede_i), _fmt_ip(rede_i + 1)
    if broad_i - rede_i >= 2:
        return _fmt_ip(rede_i + 1), _fmt_ip(broad_i - 1)
    return "—", "—"


def _papel_ip_no_bloco(ip_i, rede_i, broad_i, cidr):
    if cidr == 32:
        return "Host único (/32)", ""
    if cidr == 31:
        return "Host válido em /31 (enlace P2P)", "Em /31 os dois endereços são utilizáveis (RFC 3021)."
    if ip_i == rede_i:
        return "Endereço de rede", "Este IP identifica a sub-rede e não deve ser atribuído a host."
    if ip_i == broad_i:
        return "Endereço de broadcast", "Este IP é reservado para broadcast e não deve ser atribuído a host."
    return "Host válido", ""


def processar(ip_s, cidr, regua_count=5):
    c = _core_mascara(cidr)
    if c is None:
        raise EntradaInvalidaError("CIDR inválido para cálculo de rede.")

    parts = _parse_ipv4_parts(ip_s, "IP")
    m_i = c["_m_i"]
    ip_i = (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    r_i = ip_i & m_i
    b_i = r_i | (0xffffffff ^ m_i)
    fmt = _fmt_ip
    tamanho = c["total"]
    primeiro_host, ultimo_host = _hosts_da_subrede(r_i, b_i, cidr)

    classe, classe_faixa = _classe_ipv4_didatica(parts[0])
    ip_tipo_privacidade, ip_faixa_privacidade = _privacidade_rfc1918(parts)
    hosts_recomendados = ip_tipo_privacidade not in {"Multicast", "Reservado/Experimental"}

    and_table = []
    for oct_idx in range(4):
        shift = 24 - (oct_idx * 8)
        ip_oct = (ip_i >> shift) & 255
        mask_oct = (m_i >> shift) & 255
        and_oct = ip_oct & mask_oct
        and_table.append(
            {
                "ip_oct": ip_oct,
                "mask_oct": mask_oct,
                "and_oct": and_oct,
                "wild_oct": 255 - mask_oct,
                "ip_bin": bin(ip_oct)[2:].zfill(8),
                "mask_bin": bin(mask_oct)[2:].zfill(8),
                "and_bin": bin(and_oct)[2:].zfill(8),
            }
        )

    proximas_subredes = []
    for i in range(regua_count):
        prox = r_i + (i * tamanho)
        if prox > 0xffffffff:
            break
        broad_prox = min(prox + tamanho - 1, 0xffffffff)
        p_host, u_host = _hosts_da_subrede(prox, broad_prox, cidr)
        proximas_subredes.append(
            {
                "nome": f"Subnet {i + 1}",
                "rede": fmt(prox),
                "primeiro_host": p_host,
                "ultimo_host": u_host,
                "broadcast": fmt(broad_prox),
            }
        )

    ip_papel, ip_papel_alerta = _papel_ip_no_bloco(ip_i, r_i, b_i, cidr)
    octeto_ref, tabela_ref = _tabela_referencia_subredes(cidr)
    tabela_conv, conv_atual = _tabela_conversao_bits(cidr)
    tema = _tema_dinamico(cidr, c["total"])
    out = {k: v for k, v in c.items() if k != "_m_i"}
    gateway_sugerido = primeiro_host if hosts_recomendados else "N/A para este tipo de IP"
    gateway_alternativo = ultimo_host if hosts_recomendados else "N/A para este tipo de IP"
    resumo_prova = (
        f"IP informado: {fmt(ip_i)}\n"
        f"Máscara/CIDR: {c['mask']} /{cidr}\n"
        f"Rede: {fmt(r_i)}\n"
        f"Broadcast: {fmt(b_i)}\n"
        f"Wildcard: {c['wildcard']}\n"
        f"Hosts úteis: {c['uteis']}\n"
        f"Tipo de IP: {ip_tipo_privacidade}\n"
        f"Papel do IP: {ip_papel}\n"
        f"Gateway sugerido: {gateway_sugerido}"
    )
    resumo_prova_itens = [
        {"campo": "IP informado", "valor": fmt(ip_i)},
        {"campo": "Máscara/CIDR", "valor": f"{c['mask']} /{cidr}"},
        {"campo": "Rede", "valor": fmt(r_i)},
        {"campo": "Broadcast", "valor": fmt(b_i)},
        {"campo": "Wildcard", "valor": c["wildcard"]},
        {"campo": "Hosts úteis", "valor": c["uteis"]},
        {"campo": "Tipo de IP", "valor": ip_tipo_privacidade},
        {"campo": "Papel do IP", "valor": ip_papel},
        {"campo": "Gateway sugerido", "valor": gateway_sugerido},
    ]

    seguranca_dicas = []
    if c['uteis'] > 0:
        if cidr <= 16:
            seguranca_dicas.append({"tipo": "warning", "icon": "⚠️", "texto": f"Aviso de Scan Nmap: Um scan completo de todas as portas para {c['total']} IPs exigiria um tempo excessivo. É recomendado particionar essa rede para varreduras mais eficientes."})
        elif cidr >= 24:
            seguranca_dicas.append({"tipo": "success", "icon": "✅", "texto": f"Superfície de Ataque: Uma rede /{cidr} ({c['total']} IPs) possui superfície reduzida e varreduras com Nmap são rápidas e controladas."})
            
    if ip_papel == "Endereço de broadcast":
        seguranca_dicas.append({"tipo": "danger", "icon": "🚨", "texto": "Aviso Smurf Attack: IPs de broadcast não devem responder a pacotes ICMP Request (ping), para evitar amplificação em ataques DDoS."})
    elif "Privado" not in ip_tipo_privacidade and ip_tipo_privacidade not in ["Loopback", "APIPA", "Multicast", "Reservado/Experimental", "—"]:
        seguranca_dicas.append({"tipo": "primary", "icon": "🌍", "texto": "Aviso de Borda: Este é um IP Público. Pode estar voltado à internet. Garanta que o Firewall esteja setado como Inbound Deny All por padrão."})
    elif ip_papel == "Endereço de rede":
         seguranca_dicas.append({"tipo": "info", "icon": "ℹ️", "texto": "Network ID: Usado nas tabelas de roteamento. Scans direcionados para este IP não mapeiam hosts internos ativos diretamente."})

    out.update(
        {
            "seguranca_dicas": seguranca_dicas,
            "somente_mascara": False,
            "cidr_origem": "",
            "rede": fmt(r_i),
            "broad": fmt(b_i),
            "primeiro_host": primeiro_host,
            "ultimo_host": ultimo_host,
            "classe": classe,
            "classe_faixa": classe_faixa,
            "classe_variant": _classe_variant_css(classe),
            "primeiro_octeto": parts[0],
            "ip_tipo_privacidade": ip_tipo_privacidade,
            "ip_faixa_privacidade": ip_faixa_privacidade,
            "and_table": and_table,
            "proximas_subredes": proximas_subredes,
            "dns_info": "Servidor de nomes (ex.: 8.8.8.8, 1.1.1.1 ou DNS interno)",
            "dhcp_info": f"Faixa dinâmica sugerida: {primeiro_host} até {ultimo_host}",
            "vlan_info": "Segmentação lógica de rede (o ID da VLAN não vem do IP/máscara)",
            "wan_info": "Conexão de longa distância/Internet; normalmente usa IP público",
            "gateway_sugerido": gateway_sugerido,
            "gateway_alternativo": gateway_alternativo,
            "hosts_recomendados": hosts_recomendados,
            "ip_binario_completo": ".".join(bin(p)[2:].zfill(8) for p in parts),
            "ip_papel": ip_papel,
            "ip_papel_alerta": ip_papel_alerta,
            "regua_count": regua_count,
            "resumo_prova": resumo_prova,
            "resumo_prova_itens": resumo_prova_itens,
            "octeto_referencia": octeto_ref,
            "tabela_referencia": tabela_ref,
            "tabela_conversao_bits": tabela_conv,
            "conversao_atual": conv_atual,
            "cisco_cli": (
                "conf t\n"
                "interface g0/0\n"
                f"ip address {primeiro_host} {c['mask']}\n"
                "no shutdown"
            ),
        }
    )
    out.update(tema)
    return out


@app.route("/", methods=["GET", "POST"])
def home():
    res, erro = None, None
    ip_p, cidr_p, mask_dec_p, wildcard_p, ipv6_p = "", "", "", "", ""
    regua_count_pre = "5"
    history_limit_pre = "1"
    history_page_pre = "1"
    cidr_origem = ""
    ipv6_res = None
    invalid_fields = set()

    replay_id = request.args.get("replay", "").strip()
    history_limit_qs = request.args.get("history_limit", "").strip()
    history_page_qs = request.args.get("history_page", "").strip()
    if history_limit_qs.isdigit():
        history_limit_pre = history_limit_qs
    if history_page_qs.isdigit():
        history_page_pre = history_page_qs
    if request.method == "GET" and replay_id:
        selected = next((item for item in _history if item.get("id") == replay_id), None)
        if selected:
            ip_p = selected.get("ip_entrada", "")
            cidr_p = selected.get("cidr_entrada", "")
            mask_dec_p = selected.get("mask_entrada", "")
            wildcard_p = selected.get("wildcard_entrada", "")

    if request.method == "POST":
        logger.info("Iniciando processamento de POST na rota principal")
        ip_p = request.form.get("ip", "").strip()
        ip_entrada_original = ip_p
        ipv6_p = request.form.get("ipv6", "").strip()
        cidr_raw = request.form.get("cidr", "").strip()
        mask_dec_p = request.form.get("mask_decimal", "").strip()
        wildcard_p = request.form.get("wildcard_mask", "").strip()
        regua_count_pre = request.form.get("regua_count", "5").strip() or "5"
        history_limit_pre = request.form.get("history_limit", history_limit_pre).strip() or history_limit_pre
        history_page_pre = request.form.get("history_page", history_page_pre).strip() or history_page_pre
        modo = request.form.get("modo", "").strip().lower()

        # Resolução de DNS automática caso não seja um formato IP
        if modo != "dominio" and ip_p and not all(c.isdigit() or c == '.' for c in ip_p):
            try:
                logger.info("Tentando resolver DNS automaticamente para entrada não numérica")
                ip_p = _resolver_dns_com_cache(ip_p)
            except Exception:
                logger.exception("Falha na resolução DNS automática")
                erro = f"Não foi possível resolver o domínio informado: {ip_p}"

        try:
            regua_count = int(regua_count_pre)
        except ValueError:
            regua_count = 5
        if regua_count not in {5, 10, 15}:
            regua_count = 5
        regua_count_pre = str(regua_count)
        if not history_limit_pre.isdigit():
            history_limit_pre = "1"
        history_limit_int = int(history_limit_pre)
        if history_limit_int < 0:
            history_limit_int = 0
        if history_limit_int > MAX_HISTORY:
            history_limit_int = MAX_HISTORY
        history_limit_pre = str(history_limit_int)
        if not history_page_pre.isdigit():
            history_page_pre = "1"
        history_page_int = int(history_page_pre)
        if history_page_int < 1:
            history_page_int = 1
        history_page_pre = str(history_page_int)

        cidr_val = None
        if modo not in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6"}:
            if cidr_raw:
                modo = "cidr"
            elif mask_dec_p:
                modo = "mask"
            elif wildcard_p:
                modo = "wildcard"
            elif ipv6_p:
                modo = "ipv6"
            elif ip_p:
                modo = "autoip"
            else:
                erro = "Selecione um modo e preencha o campo correspondente."
                invalid_fields.add("modo")

        if erro is None and modo == "ipv6":
            if not ipv6_p:
                erro = "No modo IPv6, informe um endereço IPv6 válido."
                invalid_fields.add("ipv6")
            else:
                try:
                    ipv6_res = _processar_ipv6(ipv6_p)
                    _registrar_consulta(
                        {
                            "modo": modo,
                            "ip": ipv6_p,
                            "cidr": "",
                            "mask_decimal": "",
                            "wildcard_mask": "",
                        },
                        {
                            "rede": ipv6_res.get("primeiros_64", ""),
                            "broad": "N/A em IPv6",
                            "mask": ipv6_res.get("prefixo_sugerido", ""),
                            "cidr": "64",
                            "nivel_tema": "IPv6 didático",
                        },
                    )
                except EntradaInvalidaError as exc:
                    logger.warning("IPv6 inválido: %s", exc)
                    erro = str(exc)
                    invalid_fields.add("ipv6")

        if erro is None and modo == "dominio":
            # Modo dedicado: domínio/hostname -> IP e análise completa.
            # Se CIDR vier vazio, aplicamos inferência didática por classe do IP resolvido.
            dominio_digitado = ip_entrada_original
            if not dominio_digitado:
                erro = "No modo Decompor Domínio para IP, informe um domínio/hostname (ex.: google.com)."
                invalid_fields.add("ip")
            elif "." not in dominio_digitado and not dominio_digitado.replace("-", "").isalnum():
                erro = "Domínio/hostname inválido. Use algo como google.com ou servidor.local."
                invalid_fields.add("ip")
            else:
                try:
                    logger.info("Modo domínio acionado para hostname informado")
                    ip_p = _resolver_dns_com_cache(dominio_digitado)
                    if cidr_raw:
                        cidr_val = int(cidr_raw)
                        cidr_origem = (
                            f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                            "CIDR informado manualmente."
                        )
                    else:
                        cidr_val, origem_inferida = _inferir_cidr_por_ip(ip_p)
                        cidr_origem = (
                            f"Domínio '{dominio_digitado}' resolvido para {ip_p}. "
                            f"{origem_inferida}."
                        )
                except ValueError:
                    logger.warning("CIDR inválido informado no modo domínio")
                    erro = "No modo Domínio, o CIDR (se informado) deve ser um número inteiro entre 0 e 32."
                    invalid_fields.add("cidr")
                except Exception:
                    logger.exception("Erro ao resolver domínio/hostname no modo domínio")
                    erro = f"Não foi possível resolver o domínio/hostname informado: {dominio_digitado}"
                    invalid_fields.add("ip")

        elif erro is None and modo == "cidr":
            if not cidr_raw:
                erro = "No modo CIDR, preencha o campo CIDR."
                invalid_fields.add("cidr")
            else:
                try:
                    cidr_val = int(cidr_raw)
                except ValueError:
                    logger.warning("CIDR inválido no modo cidr")
                    erro = "O CIDR deve ser um número inteiro entre 0 e 32."
                    invalid_fields.add("cidr")

        elif erro is None and modo == "mask":
            if not mask_dec_p:
                erro = "No modo Máscara Decimal, preencha a máscara (ex.: 255.255.255.240)."
                invalid_fields.add("mask_decimal")
            else:
                cidr_val = mascara_dotted_para_cidr(mask_dec_p)
                if cidr_val is None:
                    try:
                        _parse_ipv4_parts(mask_dec_p, "Máscara decimal")
                        erro = (
                            "Máscara decimal inválida. Use máscara contígua "
                            "(ex.: 255.255.255.0), não valores como 255.0.255.0."
                        )
                    except EntradaInvalidaError as exc:
                        logger.warning("Máscara decimal inválida: %s", exc)
                        erro = str(exc)
                        invalid_fields.add("mask_decimal")

        elif erro is None and modo == "wildcard":
            if not wildcard_p:
                erro = "No modo Wildcard, preencha a wildcard mask (ex.: 0.0.15.255)."
                invalid_fields.add("wildcard_mask")
            else:
                cidr_val = wildcard_dotted_para_cidr(wildcard_p)
                if cidr_val is None:
                    try:
                        _parse_ipv4_parts(wildcard_p, "Wildcard mask")
                        erro = (
                            "Wildcard inválida. Use formato x.x.x.x com inverso de máscara contígua "
                            "(ex.: 0.0.15.255)."
                        )
                    except EntradaInvalidaError as exc:
                        logger.warning("Wildcard inválida: %s", exc)
                        erro = str(exc)
                        invalid_fields.add("wildcard_mask")

        elif erro is None and modo == "autoip":
            if not ip_p:
                erro = "No modo Descobrir CIDR do IP, informe um endereço IP."
                invalid_fields.add("ip")
            else:
                try:
                    cidr_val, cidr_origem = _inferir_cidr_por_ip(ip_p)
                except EntradaInvalidaError as exc:
                    logger.warning("Falha ao inferir CIDR por IP: %s", exc)
                    erro = str(exc)
                    invalid_fields.add("ip")

        if erro is None and cidr_val is not None and not (0 <= cidr_val <= 32):
            erro = "CIDR deve estar entre 0 e 32."
            invalid_fields.add("cidr")

        if erro is None and cidr_val is not None:
            try:
                if ip_p:
                    res = processar(ip_p, cidr_val, regua_count=regua_count)
                else:
                    res = processar_somente_mascara(cidr_val)
                    res["regua_count"] = regua_count

                if res is not None:
                    cidr_p = str(cidr_val)
                    if not mask_dec_p:
                        mask_dec_p = res["mask"]
                    if not wildcard_p:
                        wildcard_p = res["wildcard"]
                    if cidr_origem:
                        res["cidr_origem"] = cidr_origem
                    else:
                        res["cidr_origem"] = ""
                    res["grc_resumo"] = _grc_resumo(res)
                    _registrar_consulta(
                        {
                            "modo": modo,
                            "ip": ip_entrada_original,
                            "cidr": cidr_raw,
                            "mask_decimal": mask_dec_p,
                            "wildcard_mask": wildcard_p,
                        },
                        res,
                    )
            except EntradaInvalidaError as exc:
                logger.warning("Entrada inválida durante processamento: %s", exc)
                erro = str(exc)
            except Exception:
                logger.exception("Erro interno inesperado durante processamento principal")
                erro = "Erro interno ao processar os dados. Revise os campos e tente novamente."

    if not history_limit_pre.isdigit():
        history_limit_pre = "1"
    history_limit_int = int(history_limit_pre)
    if history_limit_int < 0:
        history_limit_int = 0
    if history_limit_int > MAX_HISTORY:
        history_limit_int = MAX_HISTORY
    if not history_page_pre.isdigit():
        history_page_pre = "1"
    history_page_int = int(history_page_pre)
    if history_page_int < 1:
        history_page_int = 1

    history_list = list(_history)
    total_history = len(history_list)
    if history_limit_int > 0:
        total_history_pages = max(1, (total_history + history_limit_int - 1) // history_limit_int)
        if history_page_int > total_history_pages:
            history_page_int = total_history_pages
        history_start = (history_page_int - 1) * history_limit_int
        history_end = history_start + history_limit_int
        history_page_items = history_list[history_start:history_end]
    else:
        total_history_pages = 1
        history_page_items = []
        history_page_int = 1

    return render_template(
        "index.html",
        res=res,
        ipv6_res=ipv6_res,
        erro=erro,
        ip_pre=ip_p,
        ipv6_pre=ipv6_p,
        cidr_pre=cidr_p,
        mask_dec_pre=mask_dec_p,
        wildcard_pre=wildcard_p,
        regua_count_pre=regua_count_pre,
        history_limit_pre=str(history_limit_int),
        history_limit=history_limit_int,
        history_limit_max=MAX_HISTORY,
        history_page=history_page_int,
        total_history_pages=total_history_pages,
        has_prev_history=history_page_int > 1,
        has_next_history=history_page_int < total_history_pages,
        invalid_fields=invalid_fields,
        history=history_list,
        history_page_items=history_page_items,
    )


@app.before_request
def _before_request_log_context():
    g.request_id = str(uuid.uuid4())[:8]
    g.started_at = time.time()
    logger.info("Request iniciada: %s %s", request.method, request.path)


@app.after_request
def _after_request_log(response):
    elapsed_ms = int((time.time() - getattr(g, "started_at", time.time())) * 1000)
    logger.info(
        "Request finalizada: status=%s tempo_ms=%s",
        response.status_code,
        elapsed_ms,
    )
    return response


@app.errorhandler(Exception)
def _handle_unexpected_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    logger.exception("Exceção não tratada capturada pelo handler global")
    return (
        render_template(
            "index.html",
            res=None,
            erro="Erro interno inesperado. O evento foi registrado em log para auditoria.",
            ip_pre="",
            cidr_pre="",
            mask_dec_pre="",
            wildcard_pre="",
            regua_count_pre="5",
        ),
        500,
    )


@app.route("/history", methods=["GET"])
def history_api():
    return jsonify({"items": list(_history)})


@app.route("/export/json", methods=["GET"])
def export_json():
    payload = {
        "generated_at": _utc_now_iso(),
        "history": list(_history),
        "last_request_id": getattr(g, "request_id", "-"),
    }
    return jsonify(payload)


@app.route("/export/pdf", methods=["GET"])
def export_pdf():
    if not _history:
        return redirect(url_for("home"))
    last = _history[0]
    lines = [
        "Relatório Didático de Rede (GRC)",
        f"Gerado em: {_utc_now_iso()}",
        f"Consulta ID: {last.get('id', '-')}",
        f"Modo: {last.get('modo', '-')}",
        f"IP entrada: {last.get('ip_entrada', '-')}",
        f"CIDR entrada: {last.get('cidr_entrada', '-')}",
        f"Máscara: {last.get('mask', '-')}",
        f"CIDR final: /{last.get('cidr', '-')}",
        f"Rede: {last.get('rede', '-')}",
        f"Broadcast: {last.get('broadcast', '-')}",
        f"Tema/Risco: {last.get('tema', '-')}",
        "",
        "Objetivo: evidência de cálculo e contexto GRC para aula/auditoria.",
    ]
    pdf_io = _gerar_pdf_simples("\n".join(lines))
    return send_file(
        pdf_io,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="relatorio_rede_grc.pdf",
    )


if __name__ == '__main__':
    _carregar_historico()
    app_host = os.getenv("APP_HOST", "127.0.0.1")
    app_port = int(os.getenv("APP_PORT", "5000"))
    app_debug = os.getenv("APP_DEBUG", "true").lower() in {"1", "true", "yes", "on"}
    app_open_browser = os.getenv("APP_OPEN_BROWSER", "true").lower() in {"1", "true", "yes", "on"}
    logger.info(
        "Inicializando aplicação local host=%s porta=%s debug=%s open_browser=%s",
        app_host,
        app_port,
        app_debug,
        app_open_browser,
    )
    if app_open_browser and app_host in {"127.0.0.1", "localhost"}:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{app_host}:{app_port}")).start()
    app.run(host=app_host, port=app_port, debug=app_debug)