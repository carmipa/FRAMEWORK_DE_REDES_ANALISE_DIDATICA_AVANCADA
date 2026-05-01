import os
import threading
import time
import uuid
import webbrowser
from urllib.parse import urlparse

from flask import Flask, abort, g, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.exceptions import HTTPException

from backend.common import (
    BASE_DIR,
    DnsResolucaoError,
    EntradaInvalidaError,
    HistoricoPersistenciaError,
    MAX_HISTORY,
    log_event,
    logger,
)
from backend.services.dns_service import resolver_dns_com_cache
from backend.services.grc_service import grc_resumo
from backend.services.history_service import (
    carregar_historico,
    list_history,
    paginate_history,
    registrar_consulta,
    utc_now_iso,
)
from backend.services.ipv4_service import (
    inferir_cidr_por_ip,
    mascara_dotted_para_cidr,
    parse_ipv4_parts,
    processar,
    processar_somente_mascara,
    wildcard_dotted_para_cidr,
)
from backend.services.ipv6_service import processar_ipv6
from backend.services.pdf_service import gerar_pdf_simples
from backend.services.problem_resolution_service import (
    DEFAULT_LOCATIONS,
    generate_packet_tracer_script,
    generate_packet_tracer_zip_buffer,
    solve_network_problem,
)

app = Flask(__name__)
REGUA_COUNT_OPCOES = {5, 10, 15, 25, 50, 100}
COMPARADOR_CIDR_PADRAO_A = "20"
COMPARADOR_CIDR_PADRAO_B = "24"
PORTAS_CATALOGO = [
    {
        "porta": "20/21",
        "protocolo_transporte": "TCP",
        "servico": "FTP",
        "categoria": "Well-known (0-1023)",
        "risco": "Atenção (credenciais em texto claro)",
        "recomendacao": "Substituir por SFTP ou FTPS",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "porta": "22",
        "protocolo_transporte": "TCP",
        "servico": "SSH",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo (se bem configurado)",
        "recomendacao": "Usar chaves RSA/Ed25519, desativar root login",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "23",
        "protocolo_transporte": "TCP",
        "servico": "Telnet",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto (sem criptografia)",
        "recomendacao": "Desabilitar e substituir por SSH",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "25",
        "protocolo_transporte": "TCP",
        "servico": "SMTP",
        "categoria": "Well-known (0-1023)",
        "risco": "Atenção (spam/relay)",
        "recomendacao": "Usar STARTTLS ou porta 587 para submissão",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "porta": "53",
        "protocolo_transporte": "UDP/TCP",
        "servico": "DNS",
        "categoria": "Well-known (0-1023)",
        "risco": "Atenção (amplificação DDoS)",
        "recomendacao": "Restringir recursão para IPs externos",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "porta": "67/68",
        "protocolo_transporte": "UDP",
        "servico": "DHCP",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo (rede local)",
        "recomendacao": "Implementar DHCP Snooping na rede",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "porta": "69",
        "protocolo_transporte": "UDP",
        "servico": "TFTP",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto (sem autenticação)",
        "recomendacao": "Uso restrito para boot de dispositivos",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "80",
        "protocolo_transporte": "TCP",
        "servico": "HTTP",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto (sem criptografia)",
        "recomendacao": "Redirecionar para HTTPS (443)",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "110",
        "protocolo_transporte": "TCP",
        "servico": "POP3",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto (texto claro)",
        "recomendacao": "Substituir por POP3S (995) ou IMAPS",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "123",
        "protocolo_transporte": "UDP",
        "servico": "NTP",
        "categoria": "Well-known (0-1023)",
        "risco": "Atenção (amplificação DDoS)",
        "recomendacao": "Usar versão atualizada, restringir consultas",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "porta": "139",
        "protocolo_transporte": "TCP",
        "servico": "NetBIOS",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto se exposto à internet",
        "recomendacao": "Bloquear no firewall de borda",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "143",
        "protocolo_transporte": "TCP",
        "servico": "IMAP",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto (texto claro)",
        "recomendacao": "Substituir por IMAPS (993)",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "389",
        "protocolo_transporte": "TCP/UDP",
        "servico": "LDAP",
        "categoria": "Well-known (0-1023)",
        "risco": "Atenção (texto claro)",
        "recomendacao": "Substituir por LDAPS (636)",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "porta": "443",
        "protocolo_transporte": "TCP",
        "servico": "HTTPS",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo",
        "recomendacao": "Manter certificados válidos e TLS 1.2/1.3",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "445",
        "protocolo_transporte": "TCP",
        "servico": "SMB",
        "categoria": "Well-known (0-1023)",
        "risco": "Alto se exposto (Ransomware)",
        "recomendacao": "Bloquear no firewall, usar VPN para acesso",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "465",
        "protocolo_transporte": "TCP",
        "servico": "SMTPS",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo",
        "recomendacao": "Substituído pela 587 (Submission), mas ainda usado",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "587",
        "protocolo_transporte": "TCP",
        "servico": "Submission",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo",
        "recomendacao": "Exigir STARTTLS para submissão",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "993",
        "protocolo_transporte": "TCP",
        "servico": "IMAPS",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo",
        "recomendacao": "Padrão seguro para leitura de e-mails",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "995",
        "protocolo_transporte": "TCP",
        "servico": "POP3S",
        "categoria": "Well-known (0-1023)",
        "risco": "Baixo",
        "recomendacao": "Padrão seguro para download de e-mails",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "1433",
        "protocolo_transporte": "TCP",
        "servico": "SQL Server",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta à internet",
        "recomendacao": "Acesso via VPN ou restrição por IP",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "1521",
        "protocolo_transporte": "TCP",
        "servico": "Oracle",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta à internet",
        "recomendacao": "Restringir acesso e exigir criptografia",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "3306",
        "protocolo_transporte": "TCP",
        "servico": "MySQL",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta à internet",
        "recomendacao": "Acesso local ou via VPN/bastion",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "3389",
        "protocolo_transporte": "TCP/UDP",
        "servico": "RDP",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta à internet",
        "recomendacao": "Restringir por VPN/firewall, exigir MFA",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "5432",
        "protocolo_transporte": "TCP",
        "servico": "PostgreSQL",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta à internet",
        "recomendacao": "Acesso local ou restrito via IP e SSL",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "5900",
        "protocolo_transporte": "TCP",
        "servico": "VNC",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto (frequentemente sem criptografia)",
        "recomendacao": "Encapsular por túnel SSH",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "6379",
        "protocolo_transporte": "TCP",
        "servico": "Redis",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto (sem auth por padrão)",
        "recomendacao": "Vincular ao localhost, habilitar senha",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "8080",
        "protocolo_transporte": "TCP",
        "servico": "HTTP Alternativo",
        "categoria": "Registered (1024-49151)",
        "risco": "Atenção (sem criptografia)",
        "recomendacao": "Usar proxy reverso com HTTPS",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "porta": "8443",
        "protocolo_transporte": "TCP",
        "servico": "HTTPS Alternativo",
        "categoria": "Registered (1024-49151)",
        "risco": "Baixo",
        "recomendacao": "Garantir certificados válidos",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "porta": "9200",
        "protocolo_transporte": "TCP",
        "servico": "Elasticsearch",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta sem auth",
        "recomendacao": "Habilitar segurança, não expor à internet",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "porta": "27017",
        "protocolo_transporte": "TCP",
        "servico": "MongoDB",
        "categoria": "Registered (1024-49151)",
        "risco": "Alto se exposta sem auth",
        "recomendacao": "Habilitar auth, vincular ao localhost",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    }
]

PROTOCOLOS_CATALOGO = [
    {
        "nome": "ARP",
        "camada": "Enlace",
        "transporte": "N/A",
        "porta_comum": "N/A",
        "funcao": "Mapeia IP (L3) para MAC Address (L2)",
        "seguro": "Não (sujeito a ARP Spoofing)",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "nome": "FTP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "20, 21",
        "funcao": "Transferência de arquivos em texto claro",
        "seguro": "Não",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "nome": "FTPS",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "990",
        "funcao": "FTP sobre SSL/TLS",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "SFTP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "22",
        "funcao": "Transferência de arquivos usando subsistema SSH",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "TELNET",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "23",
        "funcao": "Terminal virtual remoto",
        "seguro": "Não (texto claro)",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "nome": "SSH",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "22",
        "funcao": "Acesso remoto seguro e tunelamento",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "POP3",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "110",
        "funcao": "Download de e-mails (não sincroniza)",
        "seguro": "Não",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "nome": "IMAP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "143",
        "funcao": "Sincronização de mensagens no servidor",
        "seguro": "Não",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "nome": "NTP",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "123",
        "funcao": "Sincronização de relógios de rede",
        "seguro": "Não por padrão",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "nome": "LDAP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "389",
        "funcao": "Consulta a serviços de diretório",
        "seguro": "Não (usa texto claro)",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "nome": "SMB",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "445",
        "funcao": "Compartilhamento de arquivos (Windows)",
        "seguro": "Requer SMBv3 + criptografia",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "nome": "RDP",
        "camada": "Aplicação",
        "transporte": "TCP/UDP",
        "porta_comum": "3389",
        "funcao": "Acesso à área de trabalho remota",
        "seguro": "Sim (se NLA ativo), mas alvo frequente",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    },
    {
        "nome": "TLS",
        "camada": "Transporte/Sessão",
        "transporte": "TCP",
        "porta_comum": "Múltiplas",
        "funcao": "Segurança e criptografia de ponta a ponta",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "QUIC",
        "camada": "Transporte",
        "transporte": "UDP",
        "porta_comum": "443",
        "funcao": "Transporte multiplexado de baixa latência",
        "seguro": "Sim (TLS 1.3 embutido)",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "HTTP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "80",
        "funcao": "Transferência de hipertexto",
        "seguro": "Não",
        "badge": "🔴 Crítico",
        "badge_color": "danger"
    },
    {
        "nome": "HTTPS",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "443",
        "funcao": "HTTP protegido por TLS",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "HTTP/3",
        "camada": "Aplicação",
        "transporte": "UDP (via QUIC)",
        "porta_comum": "443",
        "funcao": "Próxima geração da web (mais rápido)",
        "seguro": "Sim",
        "badge": "🟢 Seguro",
        "badge_color": "success"
    },
    {
        "nome": "BGP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "179",
        "funcao": "Roteamento entre Sistemas Autônomos (Internet)",
        "seguro": "Não inerentemente (usa RPKI)",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "nome": "OSPF",
        "camada": "Rede/Transporte",
        "transporte": "IP (Protocolo 89)",
        "porta_comum": "N/A",
        "funcao": "Roteamento dinâmico interno baseado em Link-State",
        "seguro": "Pode usar autenticação MD5/SHA",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "nome": "RIP",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "520",
        "funcao": "Roteamento baseado em vetor de distância",
        "seguro": "Não (RIPv1) / Autenticado (RIPv2)",
        "badge": "🔵 Didático",
        "badge_color": "info"
    },
    {
        "nome": "DNS",
        "camada": "Aplicação",
        "transporte": "UDP/TCP",
        "porta_comum": "53",
        "funcao": "Resolução de nomes",
        "seguro": "Não por padrão (usar DNSSEC/DoH)",
        "badge": "🟡 Atenção",
        "badge_color": "warning"
    }
]


def _alternativa_segura_porta(item: dict) -> str:
    alternativa = (item.get("alternativa_segura") or "").strip()
    if alternativa:
        return alternativa
    servico = (item.get("servico") or "").strip().lower()
    mapa = {
        "ftp": "SFTP ou FTPS",
        "telnet": "SSH",
        "http": "HTTPS (TLS)",
        "http alternativo": "HTTPS (443/8443)",
        "pop3": "POP3S (995) ou IMAPS (993)",
        "imap": "IMAPS (993)",
        "ldap": "LDAPS (636)",
        "netbios": "SMBv3 restrito + VPN",
        "smb": "SMB assinado via VPN",
        "rdp": "Acesso via VPN + MFA",
        "vnc": "VNC via tunel SSH",
        "sql server": "Acesso privado via VPN/bastion",
        "oracle": "Acesso privado + criptografia",
        "mysql": "Acesso privado via VPN/bastion",
        "postgresql": "Acesso privado + SSL",
        "redis": "Redis local com auth e TLS",
        "elasticsearch": "Acesso privado com auth e TLS",
        "mongodb": "Acesso privado com auth e TLS",
        "dns": "DNS restrito + DNSSEC (quando aplicavel)",
        "dhcp": "DHCP Snooping + segmentacao VLAN",
        "ntp": "NTP autenticado e restrito",
        "https": "Manter TLS 1.2/1.3 e certificados validos",
        "https alternativo": "Manter TLS 1.2/1.3 e certificados validos",
        "smtps": "MTA-STS + TLS forte",
        "submission": "Submission 587 com STARTTLS obrigatorio",
        "imaps": "IMAPS com TLS forte",
        "pop3s": "POP3S com TLS forte",
        "ssh": "SSH com chave publica e MFA",
        "tftp": "SFTP/HTTPS para transferencia segura",
    }
    if servico in mapa:
        return mapa[servico]
    recomendacao = (item.get("recomendacao") or "").strip()
    if recomendacao:
        return recomendacao
    return "Aplicar segmentacao, firewall e criptografia ponta a ponta"


def montar_portas_catalogo_exibicao() -> list[dict]:
    saida = []
    for item in PORTAS_CATALOGO:
        linha = dict(item)
        linha["alternativa_segura"] = _alternativa_segura_porta(item)
        saida.append(linha)
    return saida


def normalizar_hostname_entrada(entrada: str) -> str:
    bruto = (entrada or "").strip()
    if not bruto:
        return ""
    parece_url = "://" in bruto or bruto.startswith("//") or any(sep in bruto for sep in ["/", "?", "#", ":"])
    if not parece_url:
        return bruto.strip(".")
    alvo_parse = bruto if "://" in bruto else f"//{bruto}"
    parsed = urlparse(alvo_parse, scheme="http")
    if parsed.hostname:
        return parsed.hostname.strip().strip(".")
    return bruto.strip(".")


def montar_wizard_calculo(res):
    if not res or res.get("somente_mascara"):
        return []
    texto_classe = f"Classe {res.get('classe')} ({res.get('classe_faixa')})."
    if res.get("classe_observacao"):
        texto_classe += f" {res.get('classe_observacao')}"
    return [
        {
            "icone": "🧭",
            "etapa": "Classe/faixa",
            "acao": f"Identificar o 1º octeto ({res.get('primeiro_octeto')})",
            "resultado": texto_classe,
        },
        {
            "icone": "📏",
            "etapa": "Máscara",
            "acao": f"Converter /{res.get('cidr')} para máscara",
            "resultado": f"{res.get('mask')} (wildcard {res.get('wildcard')}).",
        },
        {
            "icone": "🧠",
            "etapa": "Rede (AND)",
            "acao": "Aplicar IP & máscara",
            "resultado": f"Rede calculada: {res.get('rede')}.",
        },
        {
            "icone": "📣",
            "etapa": "Hosts/Broadcast",
            "acao": "Calcular intervalo de hosts",
            "resultado": (
                f"1º útil {res.get('primeiro_host')} | "
                f"último útil {res.get('ultimo_host')} | "
                f"broadcast {res.get('broad')}."
            ),
        },
    ]


def montar_timeline_bloco(res):
    if not res or res.get("somente_mascara"):
        return None
    papel = (res.get("ip_papel") or "").lower()
    if "rede" in papel:
        posicao = "rede"
    elif "broadcast" in papel:
        posicao = "broadcast"
    else:
        posicao = "hosts"
    return {
        "rede": res.get("rede"),
        "primeiro_host": res.get("primeiro_host"),
        "ultimo_host": res.get("ultimo_host"),
        "broadcast": res.get("broad"),
        "ip": res.get("resumo_prova_itens", [{}])[0].get("valor", ""),
        "posicao": posicao,
    }


def explicar_erro_didatico(erro):
    txt = (erro or "").strip()
    if not txt:
        return None
    rules = [
        (
            "IP inválido",
            "O campo IP deve estar em IPv4 com 4 octetos numéricos.",
            "Use formato x.x.x.x (ex.: 172.19.0.10).",
        ),
        (
            "CIDR",
            "O prefixo precisa ser inteiro entre 0 e 32.",
            "Exemplos válidos: 8, 16, 20, 24, 30.",
        ),
        (
            "Máscara decimal inválida",
            "A máscara precisa ter bits contíguos de rede.",
            "Use máscara contínua, como 255.255.255.0.",
        ),
        (
            "Wildcard inválida",
            "A wildcard deve ser o inverso de uma máscara contígua.",
            "Ex.: 0.0.15.255 corresponde a /20.",
        ),
        (
            "domínio",
            "O domínio/hostname não pôde ser resolvido no DNS.",
            "Teste com google.com e confira conectividade DNS.",
        ),
    ]
    lower = txt.lower()
    for marker, causa, como in rules:
        if marker.lower() in lower:
            return {"causa": causa, "como_corrigir": como}
    return {
        "causa": "A entrada não passou nas validações do modo selecionado.",
        "como_corrigir": "Revise os campos obrigatórios do modo e tente novamente.",
    }


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
    wizard_calculo = []
    timeline_bloco = None
    erro_didatico = None
    comparador_cidr_a_pre = COMPARADOR_CIDR_PADRAO_A
    comparador_cidr_b_pre = COMPARADOR_CIDR_PADRAO_B
    comparador_cards = []
    comparador_only = False
    comparador_ip = ""
    active_tab_pre = request.args.get("tab", "cidr").strip().lower() or "cidr"

    replay_id = request.args.get("replay", "").strip()
    history_limit_qs = request.args.get("history_limit", "").strip()
    history_page_qs = request.args.get("history_page", "").strip()
    if history_limit_qs.isdigit():
        history_limit_pre = history_limit_qs
    if history_page_qs.isdigit():
        history_page_pre = history_page_qs
    if request.method == "GET" and replay_id:
        selected = next((item for item in list_history() if item.get("id") == replay_id), None)
        if selected:
            modo_replay = (selected.get("modo") or "").strip().lower()
            if modo_replay in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "portas", "protocolos"}:
                active_tab_pre = modo_replay
            if selected.get("modo") == "ipv6":
                ipv6_p = selected.get("ipv6_entrada") or selected.get("ip_entrada", "")
                ip_p = ""
            else:
                ip_p = selected.get("ip_entrada", "")
                ipv6_p = selected.get("ipv6_entrada", "")
            cidr_p = selected.get("cidr_entrada", "")
            mask_dec_p = selected.get("mask_entrada", "")
            wildcard_p = selected.get("wildcard_entrada", "")

    if request.method == "POST":
        log_event("info", "calc_request", status="start")
        ip_p = request.form.get("ip", "").strip()
        ip_entrada_original = ip_p
        ipv6_p = request.form.get("ipv6", "").strip()
        cidr_raw = request.form.get("cidr", "").strip()
        mask_dec_p = request.form.get("mask_decimal", "").strip()
        wildcard_p = request.form.get("wildcard_mask", "").strip()
        regua_count_pre = request.form.get("regua_count", "5").strip() or "5"
        comparador_cidr_a_pre = (
            request.form.get("comparador_cidr_a", COMPARADOR_CIDR_PADRAO_A).strip() or COMPARADOR_CIDR_PADRAO_A
        )
        comparador_cidr_b_pre = (
            request.form.get("comparador_cidr_b", COMPARADOR_CIDR_PADRAO_B).strip() or COMPARADOR_CIDR_PADRAO_B
        )
        history_limit_pre = request.form.get("history_limit", history_limit_pre).strip() or history_limit_pre
        history_page_pre = request.form.get("history_page", history_page_pre).strip() or history_page_pre
        modo = request.form.get("modo", "").strip().lower()
        active_tab_pre = modo or active_tab_pre

        try:
            regua_count = int(regua_count_pre)
        except ValueError:
            regua_count = 5
        if regua_count not in REGUA_COUNT_OPCOES:
            regua_count = 5
        regua_count_pre = str(regua_count)

        cidr_val = None
        forcar_somente_mascara = False
        if modo not in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "portas", "protocolos"}:
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

        # Resolve DNS automático apenas quando o modo depende de IP de host.
        if (
            erro is None
            and modo in {"cidr", "autoip", "comparador"}
            and ip_p
            and not all(c.isdigit() or c == "." for c in ip_p)
        ):
            try:
                log_event("info", "dns_autoresolve", status="start", modo=modo)
                ip_p = resolver_dns_com_cache(ip_p)
            except DnsResolucaoError as exc:
                logger.warning("evento=dns_autoresolve status=error modo=%s erro=%s", modo, exc)
                erro = f"Não foi possível resolver o domínio informado: {ip_p}"

        if erro is None and modo == "ipv6":
            if not ipv6_p:
                erro = "No modo IPv6, informe um endereço IPv6 válido."
                invalid_fields.add("ipv6")
            else:
                try:
                    ipv6_res = processar_ipv6(ipv6_p)
                    registrar_consulta(
                        {
                            "modo": modo,
                            "ip": "",
                            "ipv6": ipv6_p,
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
                    logger.warning("evento=calc status=invalid_input modo=ipv6 erro=%s", exc)
                    erro = str(exc)
                    invalid_fields.add("ipv6")

        if erro is None and modo == "dominio":
            dominio_digitado = normalizar_hostname_entrada(ip_entrada_original)
            if not dominio_digitado:
                erro = "No modo Decompor Domínio para IP, informe um domínio/hostname (ex.: google.com)."
                invalid_fields.add("ip")
            elif "." not in dominio_digitado and not dominio_digitado.replace("-", "").isalnum():
                erro = "Domínio/hostname inválido. Use algo como google.com ou servidor.local."
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
                    logger.warning("evento=calc status=invalid_input modo=dominio campo=cidr")
                    erro = "No modo Domínio, o CIDR (se informado) deve ser um número inteiro entre 0 e 32."
                    invalid_fields.add("cidr")
                except DnsResolucaoError as exc:
                    logger.warning("evento=calc status=dns_error modo=dominio erro=%s", exc)
                    erro = str(exc)
                    invalid_fields.add("ip")

        elif erro is None and modo == "cidr":
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

        elif erro is None and modo == "mask":
            cidr_i = mascara_dotted_para_cidr(ip_p) if ip_p else None
            cidr_m = mascara_dotted_para_cidr(mask_dec_p) if mask_dec_p else None
            forcar_somente_mascara = False
            if not mask_dec_p and not ip_p:
                erro = (
                    "No modo Máscara Decimal, informe a máscara contígua (ex.: 255.255.255.240). "
                    "Esta aba é só para análise da máscara/prefixo; com IP + máscara use a aba CIDR."
                )
                invalid_fields.add("mask_decimal")
                invalid_fields.add("ip")
            elif mask_dec_p and cidr_m is None:
                try:
                    parse_ipv4_parts(mask_dec_p, "Máscara decimal")
                    erro = (
                        "Máscara decimal inválida. Use máscara contígua "
                        "(ex.: 255.255.255.0), não valores como 255.0.255.0."
                    )
                except EntradaInvalidaError as exc:
                    logger.warning("evento=calc status=invalid_input modo=mask campo=mask_decimal erro=%s", exc)
                    erro = str(exc)
                    invalid_fields.add("mask_decimal")
            elif not mask_dec_p and ip_p:
                if cidr_i is not None:
                    cidr_val = cidr_i
                    cidr_origem = (
                        f"O valor no campo “Endereço IPv4” é uma máscara contígua (→ /{cidr_val}). "
                        "Dica: coloque a máscara no campo Máscara ou deixe o IP vazio — o / (barra) da aula é o do exercício."
                    )
                    forcar_somente_mascara = True
                else:
                    try:
                        cidr_val, origem_inferida = inferir_cidr_por_ip(ip_p)
                        cidr_origem = f"CIDR inferido automaticamente pelo IP informado. {origem_inferida}."
                    except EntradaInvalidaError as exc:
                        logger.warning("evento=calc status=invalid_input modo=mask campo=ip erro=%s", exc)
                        erro = str(exc)
                        invalid_fields.add("ip")
            elif mask_dec_p and not ip_p:
                cidr_val = cidr_m
                cidr_origem = f"Máscara {mask_dec_p} convertida para /{cidr_val}."
            else:
                if cidr_i is not None and cidr_m is not None and cidr_i != cidr_m:
                    if ip_p.strip().startswith("255."):
                        cidr_val = cidr_i
                        cidr_origem = (
                            f"Conflito: o / (barra) usado na aula é /{cidr_val} (máscara 255.x no campo IP, p. ex. /18). "
                            f"O campo Máscara decimal apontava para /{cidr_m} — deixe só um conjunto coerente."
                        )
                        forcar_somente_mascara = True
                    else:
                        cidr_val = cidr_m
                        cidr_origem = (
                            f"Usando /{cidr_val} a partir do campo Máscara decimal. "
                            f"O endereço {ip_p} também se lê como máscara (→ /{cidr_i}) — use um host (ex.: 10.0.0.1) "
                            "se o exercício for o AND com a máscara do outro campo."
                        )
                elif cidr_i is not None and cidr_m is not None and cidr_i == cidr_m:
                    cidr_val = cidr_m
                    cidr_origem = f"Máscara {mask_dec_p} (e o valor no IP) → /{cidr_val}."
                else:
                    cidr_val = cidr_m
                    cidr_origem = f"Máscara {mask_dec_p} → /{cidr_val} (rede calculada com o IP {ip_p})."

        elif erro is None and modo == "wildcard":
            if not ip_p and not wildcard_p:
                erro = "No modo Wildcard, informe os dois campos: IP e wildcard mask."
                invalid_fields.add("ip")
                invalid_fields.add("wildcard_mask")
            elif not ip_p:
                erro = "No modo Wildcard, informe também o endereço IP."
                invalid_fields.add("ip")
            elif not wildcard_p:
                erro = "No modo Wildcard, preencha também a wildcard mask (ex.: 0.0.15.255)."
                invalid_fields.add("wildcard_mask")
            else:
                cidr_val = wildcard_dotted_para_cidr(wildcard_p)
                if cidr_val is None:
                    try:
                        parse_ipv4_parts(wildcard_p, "Wildcard mask")
                        erro = (
                            "Wildcard inválida. Use formato x.x.x.x com inverso de máscara contígua "
                            "(ex.: 0.0.15.255)."
                        )
                    except EntradaInvalidaError as exc:
                        logger.warning("evento=calc status=invalid_input modo=wildcard campo=wildcard_mask erro=%s", exc)
                        erro = str(exc)
                        invalid_fields.add("wildcard_mask")

        elif erro is None and modo == "autoip":
            if not ip_p:
                erro = "No modo Descobrir CIDR do IP, informe um endereço IP."
                invalid_fields.add("ip")
            else:
                try:
                    cidr_val, cidr_origem = inferir_cidr_por_ip(ip_p)
                except EntradaInvalidaError as exc:
                    logger.warning("evento=calc status=invalid_input modo=autoip campo=ip erro=%s", exc)
                    erro = str(exc)
                    invalid_fields.add("ip")
        elif erro is None and modo == "comparador":
            comparador_only = True
            if not ip_p:
                erro = "No modo Comparador CIDR, informe um endereço IP."
                invalid_fields.add("ip")
            else:
                cidrs_txt = [comparador_cidr_a_pre, comparador_cidr_b_pre]
                for idx, cidr_txt in enumerate(cidrs_txt, start=1):
                    if not cidr_txt.isdigit():
                        erro = f"CIDR {idx} do comparador deve ser número inteiro entre 0 e 32."
                        break
                    cidr_cmp = int(cidr_txt)
                    if not (0 <= cidr_cmp <= 32):
                        erro = f"CIDR {idx} do comparador deve estar entre 0 e 32."
                        break
                if erro is None:
                    try:
                        comparador_ip = ip_p
                        for cidr_txt in cidrs_txt:
                            cidr_cmp = int(cidr_txt)
                            cmp_res = processar(ip_p, cidr_cmp, regua_count=5)
                            comparador_cards.append(
                                {
                                    "cidr": cidr_cmp,
                                    "mask": cmp_res["mask"],
                                    "pulo": cmp_res["pulo"],
                                    "uteis": cmp_res["uteis"],
                                    "rede": cmp_res["rede"],
                                    "broadcast": cmp_res["broad"],
                                    "nivel_tema": cmp_res["nivel_tema"],
                                }
                            )
                    except EntradaInvalidaError as exc:
                        erro = str(exc)
                        invalid_fields.add("ip")

        if erro is None and cidr_val is not None and not (0 <= cidr_val <= 32):
            erro = "CIDR deve estar entre 0 e 32."
            invalid_fields.add("cidr")

        if erro is None and cidr_val is not None:
            # Se o "IP" é na verdade uma máscara (ex.: 255.255.192.0), não usar lógica de host:
            # o 1º octeto 255 seria mostrado como classe E — o desejado é o modo sub-rede (A/B/C pelo /).
            ci_como_mascara = mascara_dotted_para_cidr(ip_p) if ip_p else None
            if ci_como_mascara is not None and not forcar_somente_mascara:
                if ci_como_mascara != cidr_val:
                    cidr_val = ci_como_mascara
                    cidr_origem = (
                        f"O texto no campo de endereço é uma máscara contígua (→ /{cidr_val}). "
                        "O número depois do / foi alinhado a essa máscara para não classificar 255.x como host "
                        "(como faixa E)."
                    )
                else:
                    suf = (
                        " Campo de endereço reconhecido como máscara pontuada — análise só sub-rede "
                        "(referência de classe pelo prefixo /), não pelo 1º octeto como host."
                    )
                    cidr_origem = ((cidr_origem or "").strip() + suf).strip()
                forcar_somente_mascara = True
            try:
                if forcar_somente_mascara:
                    res = processar_somente_mascara(cidr_val)
                elif ip_p:
                    res = processar(ip_p, cidr_val, regua_count=regua_count)
                else:
                    res = processar_somente_mascara(cidr_val)
                if res is not None and res.get("somente_mascara"):
                    res["regua_count"] = regua_count

                if res is not None:
                    cidr_p = str(cidr_val)
                    if not mask_dec_p:
                        mask_dec_p = res["mask"]
                    if not wildcard_p:
                        wildcard_p = res["wildcard"]
                    res["cidr_origem"] = cidr_origem or ""
                    res["grc_resumo"] = grc_resumo(res)
                    try:
                        registrar_consulta(
                            {
                                "modo": modo,
                                "ip": ip_entrada_original,
                                "cidr": cidr_raw,
                                "mask_decimal": mask_dec_p,
                                "wildcard_mask": wildcard_p,
                            },
                            res,
                        )
                    except HistoricoPersistenciaError as exc:
                        logger.warning("evento=history_persist status=warn modo=%s erro=%s", modo, exc)
            except EntradaInvalidaError as exc:
                logger.warning("evento=calc status=invalid_input modo=%s erro=%s", modo, exc)
                erro = str(exc)
            except Exception:
                logger.exception("evento=calc status=error modo=%s", modo)
                erro = "Erro interno ao processar os dados. Revise os campos e tente novamente."

        if res and not res.get("somente_mascara"):
            wizard_calculo = montar_wizard_calculo(res)
            timeline_bloco = montar_timeline_bloco(res)

        if erro:
            erro_didatico = explicar_erro_didatico(erro)

    pag = paginate_history(history_limit_pre, history_page_pre)
    return render_template(
        "index.html",
        active_main_menu="analise",
        res=res,
        ipv6_res=ipv6_res,
        erro=erro,
        ip_pre=ip_p,
        ipv6_pre=ipv6_p,
        cidr_pre=cidr_p,
        mask_dec_pre=mask_dec_p,
        wildcard_pre=wildcard_p,
        regua_count_pre=regua_count_pre,
        comparador_cidr_a_pre=comparador_cidr_a_pre,
        comparador_cidr_b_pre=comparador_cidr_b_pre,
        comparador_cards=comparador_cards,
        comparador_only=comparador_only,
        comparador_ip=comparador_ip,
        active_tab_pre=active_tab_pre,
        wizard_calculo=wizard_calculo,
        timeline_bloco=timeline_bloco,
        erro_didatico=erro_didatico,
        history_limit_pre=pag["history_limit_pre"],
        history_limit=pag["history_limit"],
        history_limit_max=pag["history_limit_max"],
        history_page=pag["history_page"],
        total_history_pages=pag["total_history_pages"],
        has_prev_history=pag["has_prev_history"],
        has_next_history=pag["has_next_history"],
        invalid_fields=invalid_fields,
        history=pag["history"],
        history_page_items=pag["history_page_items"],
        portas_catalogo=montar_portas_catalogo_exibicao(),
        protocolos_catalogo=PROTOCOLOS_CATALOGO,
    )


@app.route("/resolucao-problemas", methods=["GET", "POST"])
def resolucao_problemas():
    erro = None
    invalid_fields = set()
    form_data = {"base_network": "172.21.0.0/16", "topology_type": "ring"}
    locations = [dict(item) for item in DEFAULT_LOCATIONS]
    scenario = None

    if request.method == "POST":
        action_type = request.form.get("action_type", "calculate").strip().lower()
        form_data = {
            "base_network": request.form.get("base_network", "").strip(),
            "topology_type": request.form.get("topology_type", "ring").strip().lower() or "ring",
        }
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

        try:
            scenario = solve_network_problem(
                form_data["base_network"],
                locations,
                topology_type=form_data["topology_type"],
            )
            if action_type == "export":
                content = generate_packet_tracer_script(scenario)
                filename = "config_packet_tracer_consolidado.txt"
                return app.response_class(
                    content,
                    mimetype="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'},
                )
            if action_type == "export_zip":
                zip_file = generate_packet_tracer_zip_buffer(scenario)
                return send_file(
                    zip_file,
                    mimetype="application/zip",
                    as_attachment=True,
                    download_name="laboratorio_packet_tracer.zip",
                )
        except EntradaInvalidaError as exc:
            erro = str(exc)
            if not form_data["base_network"]:
                invalid_fields.add("base_network")
            if not locations:
                invalid_fields.add("loc_hosts")
            if form_data["topology_type"] not in {"ring", "mesh"}:
                invalid_fields.add("topology_type")

    return render_template(
        "resolucao_problemas.html",
        active_main_menu="resolucao",
        erro=erro,
        invalid_fields=invalid_fields,
        form_data=form_data,
        locations=locations,
        scenario=scenario,
    )


@app.before_request
def _before_request_log_context():
    g.request_id = str(uuid.uuid4())[:8]
    g.started_at = time.time()
    log_event("info", "request", status="start", method=request.method, path=request.path)


@app.after_request
def _after_request_log(response):
    elapsed_ms = int((time.time() - getattr(g, "started_at", time.time())) * 1000)
    log_event("info", "request", status="end", code=response.status_code, elapsed_ms=elapsed_ms, path=request.path)
    return response


@app.errorhandler(Exception)
def _handle_unexpected_error(exc):
    if isinstance(exc, HTTPException):
        return exc
    logger.exception("evento=global_exception status=error tipo=%s", exc.__class__.__name__)
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
    return jsonify({"items": list_history()})


@app.route("/history/catalog", methods=["POST"])
def history_catalog():
    payload = request.get_json(silent=True) or {}
    modo = (payload.get("modo") or "").strip().lower()
    if modo not in {"portas", "protocolos"}:
        return jsonify({"ok": False, "erro": "modo inválido"}), 400
    entrada = payload.get("entrada") or ""
    try:
        registrar_consulta(
            {
                "modo": modo,
                "ip": entrada,
                "ipv6": "",
                "cidr": "",
                "mask_decimal": "",
                "wildcard_mask": "",
            },
            {
                "rede": "N/A",
                "broad": "N/A",
                "mask": "N/A",
                "cidr": "",
                "nivel_tema": f"Consulta de catálogo: {modo}",
            },
        )
    except HistoricoPersistenciaError as exc:
        logger.warning("evento=history_catalog status=warn modo=%s erro=%s", modo, exc)
        return jsonify({"ok": False, "erro": "persistencia_indisponivel"}), 503
    return jsonify({"ok": True})


@app.route("/export/json", methods=["GET"])
def export_json():
    payload = {
        "generated_at": utc_now_iso(),
        "history": list_history(),
        "last_request_id": getattr(g, "request_id", "-"),
    }
    return jsonify(payload)


@app.route("/export/pdf", methods=["GET"])
def export_pdf():
    history = list_history()
    if not history:
        return redirect(url_for("home"))
    last = history[0]
    lines = [
        "Relatório Didático de Rede (GRC)",
        f"Gerado em: {utc_now_iso()}",
        f"Consulta ID: {last.get('id', '-')}",
        f"Modo: {last.get('modo', '-')}",
        f"Entrada: {last.get('ipv6_entrada') or last.get('ip_entrada', '-')}",
        f"CIDR entrada: {last.get('cidr_entrada', '-')}",
        f"Máscara: {last.get('mask', '-')}",
        f"CIDR final: /{last.get('cidr', '-')}",
        f"Rede: {last.get('rede', '-')}",
        f"Broadcast: {last.get('broadcast', '-')}",
        f"Tema/Risco: {last.get('tema', '-')}",
        "",
        "Objetivo: evidência de cálculo e contexto GRC para aula/auditoria.",
    ]
    pdf_io = gerar_pdf_simples("\n".join(lines))
    return send_file(
        pdf_io,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="relatorio_rede_grc.pdf",
    )


@app.route("/icone.png", methods=["GET"])
def project_icon():
    icon_path = BASE_DIR / "icone.png"
    if not icon_path.exists():
        abort(404)
    return send_file(icon_path, mimetype="image/png")


if __name__ == "__main__":
    try:
        carregar_historico()
    except HistoricoPersistenciaError as exc:
        logger.warning("evento=app_boot status=history_unavailable erro=%s", exc)
    app_host = os.getenv("APP_HOST", "127.0.0.1")
    app_port_raw = os.getenv("APP_PORT", "5000")
    try:
        app_port = int(app_port_raw)
    except ValueError:
        logger.warning("evento=app_boot status=invalid_port app_port_raw=%s fallback=5000", app_port_raw)
        app_port = 5000
    app_debug = os.getenv("APP_DEBUG", "true").lower() in {"1", "true", "yes", "on"}
    app_open_browser = os.getenv("APP_OPEN_BROWSER", "true").lower() in {"1", "true", "yes", "on"}
    log_event(
        "info",
        "app_boot",
        status="start",
        host=app_host,
        port=app_port,
        debug=app_debug,
        open_browser=app_open_browser,
    )
    if app_open_browser and app_host in {"127.0.0.1", "localhost"}:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://{app_host}:{app_port}")).start()
    app.run(host=app_host, port=app_port, debug=app_debug)

