import os
import threading
import time
import uuid
import webbrowser

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
from backend.services.geo_lookup_service import (
    cliente_ip_efetivo,
    lookup_regiao_geografica,
    normalizar_ip_digitado,
)
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
from backend.services.home_web_helpers import (
    explicar_erro_didatico,
    montar_timeline_bloco,
    montar_wizard_calculo,
    motivo_analise,
    normalizar_hostname_entrada,
)
from backend.services.pdf_service import gerar_pdf_simples
from backend.services.problem_resolution_service import (
    DEFAULT_LOCATIONS,
    generate_entrega_relatorio_txt,
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
        "nome": "BGP-4 / eBGP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "179",
        "funcao": "Entre Sistemas Autônomos (eBGP): políticas, AS-PATH, escolha de rotas na Internet",
        "seguro": "TCP; no mundo real usar RPKI/ROV quando aplicável",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "EGP",
        "algoritmo": "Path Vector",
        "metrica": "AS-PATH, LOCAL_PREF, MED, Weight (vendor)",
        "distancia_administrativa": "20 (eBGP)",
        "atualizacao": "Incremental por evento (sessão TCP 179)",
        "sintaxe_base": "router bgp <AS_LOCAL> | neighbor <IP_VIZINHO> remote-as <AS_REMOTO> | network <REDE> mask <MASCARA>",
        "dica_didatica": "EGP moderno na prática = BGP entre AS; orientado a política, não menor custo interno.",
    },
    {
        "nome": "OSPFv2",
        "camada": "Rede",
        "transporte": "IP (Protocolo 89)",
        "porta_comum": "N/A",
        "funcao": "IGP link-state IPv4: áreas OSPF, LSDB, SPF, Router-ID",
        "seguro": "Autenticação MD5/SHA por área/interface",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Link-State (SPF / Dijkstra)",
        "metrica": "Cost (baseado em banda)",
        "distancia_administrativa": "110",
        "atualizacao": "LSA por evento + hellos periódicos",
        "sintaxe_base": "router ospf <PROCESS_ID> | network <REDE> <WILDCARD> area <AREA_ID>",
        "dica_didatica": "No OSPF usa-se wildcard na instrução network; backbone é a área 0.",
    },
    {
        "nome": "OSPFv3",
        "camada": "Rede",
        "transporte": "IP (Protocolo 89)",
        "porta_comum": "N/A",
        "funcao": "IGP link-state IPv6 (instâncias por link; suporte AF)",
        "seguro": "Autenticação IPsec ou nativa por interface",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Link-State (SPF / Dijkstra)",
        "metrica": "Cost",
        "distancia_administrativa": "110",
        "atualizacao": "LSA por evento + hellos periódicos",
        "sintaxe_base": "ipv6 router ospf <PROCESS_ID> | interface <IF> | ipv6 ospf <PROCESS_ID> area <AREA_ID>",
        "dica_didatica": "No OSPFv3 a ativação costuma ser por interface no IPv6.",
    },
    {
        "nome": "RIPv1",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "520",
        "funcao": "IGP vetor de distância classful (redes por classe); broadcast; hop máx 15",
        "seguro": "Sem autenticação forte",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Distance Vector",
        "metrica": "Hop count (máximo 15)",
        "distancia_administrativa": "120",
        "atualizacao": "Periódica (30s)",
        "sintaxe_base": "router rip | network <REDE_CLASSFUL>",
        "dica_didatica": "Classful: não envia máscara, limitado para redes sem VLSM.",
    },
    {
        "nome": "RIPv2",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "520",
        "funcao": "IGP vetor de distância classless (VLSM), multicast 224.0.0.9, campo next-hop",
        "seguro": "MD5 opcional",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Distance Vector",
        "metrica": "Hop count (máximo 15)",
        "distancia_administrativa": "120",
        "atualizacao": "Periódica (30s) + triggered updates",
        "sintaxe_base": "router rip | version 2 | network <REDE> | no auto-summary",
        "dica_didatica": "Do PPT: RIP v2 + no auto-summary para cenários classless com VLSM.",
    },
    {
        "nome": "EIGRP",
        "camada": "Rede",
        "transporte": "IP (Protocolo 88)",
        "porta_comum": "N/A",
        "funcao": "IGP híbrido Cisco (DUAL): métrica composta, convergência rápida",
        "seguro": "Autenticação opcional",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "DUAL (híbrido avançado)",
        "metrica": "Composta (bandwidth + delay; opcional load/reliability)",
        "distancia_administrativa": "90 (interna) / 170 (externa)",
        "atualizacao": "Parcial e por evento",
        "sintaxe_base": "router eigrp <AS> | network <REDE> <WILDCARD> | no auto-summary",
        "dica_didatica": "Convergência rápida via sucessor e feasible successor.",
    },
    {
        "nome": "IGRP",
        "camada": "Rede",
        "transporte": "IP (Protocolo 9)",
        "porta_comum": "N/A",
        "funcao": "IGP vetor de distância Cisco (legado); antecessor do EIGRP",
        "seguro": "Autenticação simples",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Distance Vector",
        "metrica": "Composta (bandwidth, delay, load, reliability)",
        "distancia_administrativa": "100",
        "atualizacao": "Periódica (90s)",
        "sintaxe_base": "router igrp <AS> | network <REDE_CLASSFUL>",
        "dica_didatica": "Legado Cisco; substituído por EIGRP em projetos modernos.",
    },
    {
        "nome": "IS-IS",
        "camada": "Rede",
        "transporte": "Enlace (L2) / PDU integrado",
        "porta_comum": "N/A",
        "funcao": "IGP link-state para IPv4 e IPv6 (NI); comum em ISP e backbone",
        "seguro": "Autenticação em adjacências L1/L2",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "IGP",
        "algoritmo": "Link-State (SPF)",
        "metrica": "Cost",
        "distancia_administrativa": "115",
        "atualizacao": "LSP por evento + hellos",
        "sintaxe_base": "router isis <TAG> | net <NSAP> | interface <IF> | ip router isis",
        "dica_didatica": "Muito usado em backbone/ISP por robustez e escala.",
    },
    {
        "nome": "iBGP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "179",
        "funcao": "Mesmo BGP-4, sessão dentro do mesmo AS: reflete prefixos aprendidos por eBGP",
        "seguro": "Políticas de rota + TCP; não é OSPF/EIGRP — complementa IGP interno",
        "badge": "🔵 Didático",
        "badge_color": "info",
        "alcance": "N/A",
        "algoritmo": "Path Vector",
        "metrica": "Políticas BGP (LOCAL_PREF, MED, communities)",
        "distancia_administrativa": "200",
        "atualizacao": "Incremental por evento",
        "sintaxe_base": "router bgp <AS> | neighbor <IP> remote-as <MESMO_AS> | next-hop-self (quando necessário)",
        "dica_didatica": "Dentro do mesmo AS, iBGP normalmente roda junto de um IGP (OSPF/IS-IS/EIGRP).",
    },
    # --- Extras didáticos (expansão do catálogo; revisão conjunta depois) ---
    {
        "nome": "ICMP",
        "camada": "Rede",
        "transporte": "IP (Protocolo 1)",
        "porta_comum": "N/A",
        "funcao": "Controle e diagnóstico IPv4: ping (echo), unreachable, TTL exceeded, MTU discovery",
        "seguro": "Pode ser abusado para reconhecimento; filtrar na borda",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "ICMPv6",
        "camada": "Rede",
        "transporte": "IPv6 (Next Header 58)",
        "porta_comum": "N/A",
        "funcao": "Equivalente ICMP para IPv6 + vizinhança (NDP: RS/RA, NS/NA)",
        "seguro": "Filtrar tipos sensíveis na borda; RA guard em switches",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "IPv4",
        "camada": "Rede",
        "transporte": "Enlace (encapsulamento)",
        "porta_comum": "N/A",
        "funcao": "Endereçamento e encaminhamento de pacotes na Internet (fragmentação, TTL, checksum cabeçalho)",
        "seguro": "IPSec/VPN para confidencialidade",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "IPv6",
        "camada": "Rede",
        "transporte": "Enlace (encapsulamento)",
        "porta_comum": "N/A",
        "funcao": "Sucessor IPv4: endereços 128 bits, extensões de cabeçalho, sem checksum em camada de rede",
        "seguro": "IPsec integrado ao modelo; firewall stateful obrigatório",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "DHCP",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "67/68 (servidor/cliente)",
        "funcao": "Atribuição dinâmica de IPv4 (lease), máscara, gateway, DNS",
        "seguro": "DHCP Snooping + reconhecimento de servidor autorizado",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "DHCPv6",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "546/547",
        "funcao": "Stateful DHCPv6 ou combined com SLAAC (flags IA_NA / IA_PD)",
        "seguro": "Autenticação de servidor + segmentação L2",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "SMTP",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "25",
        "funcao": "Transferência de correio entre MTAs (relay)",
        "seguro": "TLS opcional (STARTTLS); SPF/DKIM/DMARC no domínio",
        "badge": "🟡 Atenção",
        "badge_color": "warning",
    },
    {
        "nome": "SMTP (Submission)",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "587",
        "funcao": "Envio autenticado do cliente de e-mail para o servidor (RFC 6409)",
        "seguro": "STARTTLS + credenciais",
        "badge": "🟢 Seguro",
        "badge_color": "success",
    },
    {
        "nome": "SMTPS",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "465",
        "funcao": "SMTP encapsulado em TLS desde o handshake (implicit TLS)",
        "seguro": "Sim (TLS)",
        "badge": "🟢 Seguro",
        "badge_color": "success",
    },
    {
        "nome": "SNMP",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "161/162",
        "funcao": "Gestão de rede: polling de MIBs, traps de eventos",
        "seguro": "Preferir SNMPv3 (authPriv); v2c comunidades só em mgmt plane",
        "badge": "🟡 Atenção",
        "badge_color": "warning",
    },
    {
        "nome": "STP",
        "camada": "Enlace",
        "transporte": "Ethernet (BPDUs)",
        "porta_comum": "N/A",
        "funcao": "Spanning Tree IEEE 802.1D: previne loops em switches",
        "seguro": "BPDU Guard / Root Guard em portas de acesso",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "RSTP",
        "camada": "Enlace",
        "transporte": "Ethernet (BPDUs)",
        "porta_comum": "N/A",
        "funcao": "Rapid Spanning Tree (802.1w): convergência mais rápida que STP clássico",
        "seguro": "Mesmo endurecimento que STP",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "LACP",
        "camada": "Enlace",
        "transporte": "Ethernet (LACP PDUs)",
        "porta_comum": "N/A",
        "funcao": "802.3ad: agregação de links (port-channel) com negociação",
        "seguro": "Static mode onde política exige previsibilidade",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "LLDP",
        "camada": "Enlace",
        "transporte": "Ethernet",
        "porta_comum": "N/A",
        "funcao": "Descoberta de vizinhos L2/L3 padrão IEEE 802.1AB (multi-vendor)",
        "seguro": "Filtrar exposição em redes sensíveis",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "CDP",
        "camada": "Enlace",
        "transporte": "Ethernet (proprietário Cisco)",
        "porta_comum": "N/A",
        "funcao": "Descoberta de vizinhos Cisco; inventário de equipamentos",
        "seguro": "Desativar em portas de cliente/DMZ",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "NAT",
        "camada": "Rede",
        "transporte": "N/A (função em router/firewall)",
        "porta_comum": "N/A",
        "funcao": "Tradução endereços privados↔públicos (SNAT/DNAT, PAT)",
        "seguro": "Stateful firewall + logs",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "IPsec",
        "camada": "Rede",
        "transporte": "ESP/AH (IP prot 50/51)",
        "porta_comum": "UDP 500/4500 (IKE)",
        "funcao": "VPN site-to-site ou remote access: confidencialidade e integridade",
        "seguro": "Sim (quando bem configurado IKE/esp)",
        "badge": "🟢 Seguro",
        "badge_color": "success",
    },
    {
        "nome": "WireGuard",
        "camada": "Rede",
        "transporte": "UDP",
        "porta_comum": "51820",
        "funcao": "VPN moderna: crypto noise protocol, menos superfície que IPsec clássico",
        "seguro": "Sim (design minimalista)",
        "badge": "🟢 Seguro",
        "badge_color": "success",
    },
    {
        "nome": "MQTT",
        "camada": "Aplicação",
        "transporte": "TCP",
        "porta_comum": "1883 / 8883",
        "funcao": "Pub/sub IoT leve (broker); TLS tipicamente na 8883",
        "seguro": "TLS + auth forte em ambientes produtivos",
        "badge": "🟡 Atenção",
        "badge_color": "warning",
    },
    {
        "nome": "CoAP",
        "camada": "Aplicação",
        "transporte": "UDP",
        "porta_comum": "5683/5684",
        "funcao": "REST sobre UDP para dispositivos restritos (RFC 7252)",
        "seguro": "DTLS (CoAPS)",
        "badge": "🔵 Didático",
        "badge_color": "info",
    },
    {
        "nome": "DNS",
        "camada": "Aplicação",
        "transporte": "UDP/TCP",
        "porta_comum": "53",
        "funcao": "Resolução de nomes",
        "seguro": "Não por padrão (usar DNSSEC/DoH)",
        "badge": "🟡 Atenção",
        "badge_color": "warning",
    },
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
            if modo_replay in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "geo", "portas", "protocolos"}:
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
        if modo not in {"cidr", "mask", "wildcard", "autoip", "dominio", "ipv6", "comparador", "geo", "portas", "protocolos"}:
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
        if erro is None:
            log_event("info", "analysis_use", modo=modo, reason=motivo_analise(modo))

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
    active_main_menu = active_tab_pre if active_tab_pre in {"portas", "protocolos"} else "analise"
    return render_template(
        "analise/index.html",
        active_main_menu=active_main_menu,
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
            "topology_type": request.form.get("topology_type", "ring").strip().lower() or "ring",
            "wan_prefix": wan_prefix,
        }
        if form_data["base_network"] and (not form_data["base_network_ip"] or not form_data["base_network_cidr"]):
            if "/" in form_data["base_network"]:
                ip_part, cidr_part = form_data["base_network"].split("/", 1)
                form_data["base_network_ip"] = form_data["base_network_ip"] or ip_part.strip()
                form_data["base_network_cidr"] = form_data["base_network_cidr"] or cidr_part.strip()
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
                return app.response_class(
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
                return app.response_class(
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


@app.route("/informacoes", methods=["GET"])
def informacoes():
    cliente_ip = cliente_ip_efetivo(request)
    raw_digitado = (request.args.get("ip") or "").strip()

    if raw_digitado:
        norm, err_msg = normalizar_ip_digitado(raw_digitado)
        if err_msg:
            geo = {
                "ok": False,
                "motivo": "invalid",
                "mensagem": err_msg,
                "ip": raw_digitado,
            }
            consultado = raw_digitado
            modo_geo = "manual"
        else:
            geo = lookup_regiao_geografica(norm)
            consultado = norm
            modo_geo = "manual"
    else:
        geo = lookup_regiao_geografica(cliente_ip)
        consultado = cliente_ip
        modo_geo = "ligacao"

    log_event(
        "info",
        "page_view",
        page="informacoes",
        reason="Página de informações didáticas com separador de região geográfica.",
        cliente_ip=cliente_ip,
        geo_ok=geo.get("ok"),
        modo_geo=modo_geo,
    )
    return render_template(
        "geo/informacoes.html",
        active_main_menu="informacoes",
        cliente_ip=cliente_ip,
        consultado=consultado,
        modo_geo=modo_geo,
        geo=geo,
        ip_digitado_prefill=raw_digitado if raw_digitado else "",
    )


@app.route("/api/informacoes/geo", methods=["GET"])
def api_informacoes_geo():
    """JSON para atualizar o painel de região sem recarregar a página."""
    def _registrar_historico_geo(payload_geo: dict):
        consultado = (payload_geo.get("consultado") or "").strip()
        if not consultado:
            return
        ok_geo = bool(payload_geo.get("ok"))
        pais = payload_geo.get("pais") or "N/A"
        regiao = payload_geo.get("regiao") or "N/A"
        motivo = payload_geo.get("motivo") or ""
        nivel = (
            f"GeoIP: {regiao}/{pais}" if ok_geo else f"GeoIP indisponível ({motivo or 'sem detalhe'})"
        )
        try:
            registrar_consulta(
                {
                    "modo": "geo",
                    "ip": consultado,
                    "ipv6": "",
                    "cidr": "",
                    "mask_decimal": "",
                    "wildcard_mask": "",
                },
                {
                    "rede": regiao,
                    "broad": pais,
                    "mask": "N/A",
                    "cidr": "",
                    "nivel_tema": nivel,
                },
            )
        except HistoricoPersistenciaError as exc:
            logger.warning("evento=history_geo status=warn erro=%s", exc)

    cliente_ip = cliente_ip_efetivo(request)
    raw_digitado = (request.args.get("ip") or "").strip()

    if raw_digitado:
        norm, err_msg = normalizar_ip_digitado(raw_digitado)
        if err_msg:
            return jsonify(
                {
                    "cliente_ip": cliente_ip,
                    "consultado": raw_digitado,
                    "modo": "manual",
                    "ok": False,
                    "motivo": "invalid",
                    "mensagem": err_msg,
                }
            )
        geo = lookup_regiao_geografica(norm)
        payload = {
            "cliente_ip": cliente_ip,
            "consultado": norm,
            "modo": "manual",
            **geo,
        }
        _registrar_historico_geo(payload)
        return jsonify(payload)

    geo = lookup_regiao_geografica(cliente_ip)
    payload = {
        "cliente_ip": cliente_ip,
        "consultado": cliente_ip,
        "modo": "ligacao",
        **geo,
    }
    _registrar_historico_geo(payload)
    return jsonify(payload)


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
            "analise/index.html",
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

