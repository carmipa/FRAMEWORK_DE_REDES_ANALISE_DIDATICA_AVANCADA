from backend.analise.portas.portas_catalog import PORTAS_CATALOGO

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
