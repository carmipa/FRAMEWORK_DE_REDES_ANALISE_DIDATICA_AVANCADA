# 📡 API Reference - Framework de Redes

**Base URL:** `http://localhost:5000/api`  
**Versão:** 1.0  
**Autenticação:** Nenhuma (acesso aberto - aplicação didática)

---

## 📑 Sumário

- [Endpoints de Análise](#endpoints-de-análise)
- [Endpoints de Resolução](#endpoints-de-resolução)
- [Endpoints de Suporte](#endpoints-de-suporte)
- [Códigos de Status](#códigos-de-status)
- [Tratamento de Erros](#tratamento-de-erros)
- [Exemplos Completos](#exemplos-completos)

---

## 🔍 ENDPOINTS DE ANÁLISE

### 1. CIDR Analysis

**Descrição:** Analisa um IP com notação CIDR

**Endpoint:** `GET /analisar/cidr`

**Parâmetros Query:**

| Parâmetro | Tipo | Obrigatório | Descrição | Exemplo |
|-----------|------|-------------|-----------|---------|
| `ip` | string | ✅ Sim | Endereço IP | `192.168.1.5` |
| `cidr` | string | ✅ Sim | Notação CIDR | `/24` ou `24` |

**Response (200 OK):**

```json
{
  "modo": "cidr",
  "input": {
    "ip": "192.168.1.5",
    "cidr": "/24"
  },
  "resultado": {
    "rede": "192.168.1.0",
    "broadcast": "192.168.1.255",
    "primeiro_host": "192.168.1.1",
    "ultimo_host": "192.168.1.254",
    "mascara": "255.255.255.0",
    "hosts_uteis": 254,
    "total_hosts": 256,
    "prefixo": 24,
    "classe": "C",
    "tipo": "Privada"
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

**Erros Possíveis:**

```json
// 400 Bad Request - IP inválido
{
  "erro": "IP inválido: 192.168.1.999",
  "campo": "ip",
  "status": "entrada_invalida"
}

// 400 Bad Request - CIDR fora do range
{
  "erro": "CIDR deve estar entre /0 e /32",
  "campo": "cidr",
  "status": "entrada_invalida"
}
```

**Exemplo cURL:**

```bash
# Sucesso
curl -s "http://localhost:5000/api/analisar/cidr?ip=192.168.1.5&cidr=24" | jq

# Com erro
curl -s "http://localhost:5000/api/analisar/cidr?ip=999.999.999.999&cidr=24" | jq
```

**Exemplo JavaScript:**

```javascript
fetch('/api/analisar/cidr?ip=192.168.1.5&cidr=24')
  .then(res => res.json())
  .then(data => console.log(data))
  .catch(err => console.error('Erro:', err));
```

---

### 2. Máscara Analysis

**Descrição:** Analisa um IP com máscara decimal

**Endpoint:** `GET /analisar/mascara`

**Parâmetros Query:**

| Parâmetro | Tipo | Obrigatório | Descrição | Exemplo |
|-----------|------|-------------|-----------|---------|
| `ip` | string | ✅ Sim | Endereço IP | `192.168.1.5` |
| `mascara` | string | ✅ Sim | Máscara decimal | `255.255.255.0` |

**Response (200 OK):**

```json
{
  "modo": "mask",
  "input": {
    "ip": "192.168.1.5",
    "mascara": "255.255.255.0"
  },
  "resultado": {
    "rede": "192.168.1.0",
    "broadcast": "192.168.1.255",
    "mascara": "255.255.255.0",
    "cidr": "/24",
    "hosts_uteis": 254,
    "classe": "C",
    "tipo": "Privada"
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

---

### 3. Wildcard Analysis

**Descrição:** Calcula wildcard mask (inverso da máscara)

**Endpoint:** `GET /analisar/wildcard`

**Parâmetros Query:**

| Parâmetro | Tipo | Obrigatório | Descrição | Exemplo |
|-----------|------|-------------|-----------|---------|
| `mascara` | string | ✅ Sim | Máscara decimal | `255.255.255.0` |
| `cidr` | string | ❌ Opcional | Notação CIDR alternativa | `/24` |

**Response (200 OK):**

```json
{
  "modo": "wildcard",
  "input": {
    "mascara": "255.255.255.0"
  },
  "resultado": {
    "mascara": "255.255.255.0",
    "mascara_inversa": "0.0.0.255",
    "cidr": "/24",
    "uso": "ACL, OSPF network commands",
    "exemplo_ospf": "router ospf 1",
    "exemplo_acl": "access-list 1 permit 0.0.0.255"
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

---

### 4. DNS Resolution

**Descrição:** Resolve domínio para IP com análise

**Endpoint:** `GET /api/analisar/dominio`

**Parâmetros Query:**

| Parâmetro | Tipo | Obrigatório | Descrição | Exemplo |
|-----------|------|-------------|-----------|---------|
| `hostname` | string | ✅ Sim | Domínio ou hostname | `google.com` |

**Response (200 OK):**

```json
{
  "modo": "dominio",
  "input": {
    "hostname": "google.com"
  },
  "resultado": {
    "hostname": "google.com",
    "ip": "142.251.41.14",
    "classe": "A",
    "tipo": "Pública",
    "pais": "United States",
    "isp": "Google LLC",
    "geolocation": {
      "latitude": 37.3861,
      "longitude": -122.0839,
      "cidade": "Mountain View",
      "regiao": "California"
    },
    "tempo_resolucao_ms": 145
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

**Erros Possíveis:**

```json
// 400 Bad Request - Hostname vazio
{
  "erro": "Domínio/hostname vazio.",
  "status": "entrada_invalida"
}

// 503 Service Unavailable - DNS timeout
{
  "erro": "Timeout ao resolver DNS do domínio informado. Tente novamente em alguns segundos.",
  "status": "dns_timeout"
}

// 503 Service Unavailable - Domínio não existe
{
  "erro": "Não foi possível resolver o domínio/hostname informado: inexistente.test",
  "status": "dns_not_found"
}
```

---

### 5. IPv6 Analysis

**Descrição:** Análise básica de IPv6

**Endpoint:** `GET /api/analisar/ipv6`

**Parâmetros Query:**

| Parâmetro | Tipo | Obrigatório | Descrição | Exemplo |
|-----------|------|-------------|-----------|---------|
| `ipv6` | string | ✅ Sim | Endereço IPv6 | `2001:db8::1` |
| `prefixo` | string | ❌ Opcional | Prefixo IPv6 | `/64` |

**Response (200 OK):**

```json
{
  "modo": "ipv6",
  "input": {
    "ipv6": "2001:db8::1",
    "prefixo": "/64"
  },
  "resultado": {
    "ipv6_completo": "2001:0db8:0000:0000:0000:0000:0000:0001",
    "ipv6_comprimido": "2001:db8::1",
    "tipo": "Global Unicast",
    "prefixo": "/64",
    "rede": "2001:db8::/64",
    "hosts_disponiveis": 18446744073709551614,
    "primeira_rede_valida": "2001:db8:0000:0000::/64",
    "ultima_rede_valida": "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

---

## 🔧 ENDPOINTS DE RESOLUÇÃO

### 6. VLSM Planning

**Descrição:** Planeja VLSM para múltiplas localidades com topologia WAN

**Endpoint:** `POST /api/resolver/vlsm`

**Content-Type:** `application/json`

**Request Body:**

```json
{
  "rede_base": "10.0.0.0/16",
  "localidades": [
    {
      "nome": "Matriz",
      "hosts_necessarios": 500
    },
    {
      "nome": "Filial 1",
      "hosts_necessarios": 250
    },
    {
      "nome": "Filial 2",
      "hosts_necessarios": 100
    }
  ],
  "topology_type": "ring",
  "prefixo_wan": 30
}
```

**Response (200 OK):**

```json
{
  "modo": "vlsm",
  "status": "sucesso",
  "resultado": {
    "rede_base": "10.0.0.0/16",
    "topology": "ring",
    "vlans_lan": [
      {
        "localidade": "Matriz",
        "rede": "10.0.0.0/23",
        "hosts_disponiveis": 510,
        "hosts_solicitados": 500
      },
      {
        "localidade": "Filial 1",
        "rede": "10.0.2.0/24",
        "hosts_disponiveis": 254,
        "hosts_solicitados": 250
      }
    ],
    "links_wan": [
      {
        "enlace": "Matriz-Filial1",
        "rede": "10.0.4.0/30",
        "router1_ip": "10.0.4.1",
        "router2_ip": "10.0.4.2"
      }
    ],
    "cli_por_router": {
      "matriz": [
        "interface fa0/0",
        "ip address 10.0.0.1 255.255.254.0",
        "no shut"
      ]
    },
    "diagrama_mermaid": "graph TD\n  Matriz[Matriz 10.0.0.0/23]\n  Filial1[Filial1 10.0.2.0/24]\n  Matriz -->|10.0.4.0/30| Filial1"
  },
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

**Erros Possíveis:**

```json
// 400 Bad Request - Rede base inválida
{
  "erro": "CIDR inválido: 999.999.999.999/16",
  "campo": "rede_base",
  "status": "entrada_invalida"
}

// 400 Bad Request - Hosts impossíveis de alocar
{
  "erro": "Não há espaço para alocar todos os hosts solicitados",
  "motivo": "Rede base insuficiente",
  "total_hosts_solicitados": 10000,
  "hosts_disponiveis": 65534
}

// 400 Bad Request - Prefixo WAN inválido
{
  "erro": "Prefixo WAN deve estar entre 0 e 30",
  "campo": "prefixo_wan",
  "status": "entrada_invalida"
}
```

**Exemplo cURL:**

```bash
curl -X POST "http://localhost:5000/api/resolver/vlsm" \
  -H "Content-Type: application/json" \
  -d '{
    "rede_base": "10.0.0.0/16",
    "localidades": [
      {"nome": "Matriz", "hosts_necessarios": 500},
      {"nome": "Filial", "hosts_necessarios": 250}
    ],
    "topology_type": "ring",
    "prefixo_wan": 30
  }' | jq
```

---

## 📊 ENDPOINTS DE SUPORTE

### 7. Histórico

**Descrição:** Retorna histórico de consultas

**Endpoint:** `GET /api/history`

**Parâmetros Query (Opcionais):**

| Parâmetro | Tipo | Descrição | Exemplo |
|-----------|------|-----------|---------|
| `limite` | int | Máximo de resultados | `50` |
| `offset` | int | Paginação (skip) | `0` |
| `modo` | string | Filtrar por modo | `cidr` |

**Response (200 OK):**

```json
{
  "historico": [
    {
      "id": 1,
      "modo": "cidr",
      "input": {
        "ip": "192.168.1.5",
        "cidr": "/24"
      },
      "timestamp": "2026-05-08T10:30:45.123Z",
      "duracao_ms": 12
    },
    {
      "id": 2,
      "modo": "dominio",
      "input": {
        "hostname": "google.com"
      },
      "timestamp": "2026-05-08T10:31:10.456Z",
      "duracao_ms": 145
    }
  ],
  "total": 2,
  "limite": 50,
  "offset": 0
}
```

---

### 8. Export JSON

**Descrição:** Exporta histórico em JSON

**Endpoint:** `GET /api/export/json`

**Response:** Arquivo `history.json`

```json
{
  "exportado_em": "2026-05-08T10:32:00.000Z",
  "consultas": [...]
}
```

---

## 📋 CÓDIGOS DE STATUS

| Código | Descrição | Exemplo |
|--------|-----------|---------|
| **200** | OK - Requisição bem-sucedida | CIDR calculado |
| **400** | Bad Request - Entrada inválida | IP malformado |
| **404** | Not Found - Endpoint não existe | `/api/inexistente` |
| **500** | Internal Server Error | Erro não tratado |
| **503** | Service Unavailable | DNS timeout |

---

## ⚠️ TRATAMENTO DE ERROS

### Formato Padrão de Erro

```json
{
  "erro": "Descrição amigável do erro",
  "campo": "Nome do campo com problema (se aplicável)",
  "status": "Código interno: entrada_invalida, dns_timeout, etc",
  "timestamp": "2026-05-08T10:30:45.123Z"
}
```

### Categorias de Erro

**Erros do Usuário (400 Bad Request):**
- Entrada inválida
- Campo obrigatório faltando
- Formato incorreto

**Erros de Infraestrutura (503 Service Unavailable):**
- DNS timeout
- DNS não encontrado
- Erro interno

---

## 💡 EXEMPLOS COMPLETOS

### Exemplo 1: Análise CIDR Simples

```bash
# Request
curl "http://localhost:5000/api/analisar/cidr?ip=10.0.0.0&cidr=/8"

# Response
{
  "modo": "cidr",
  "resultado": {
    "rede": "10.0.0.0",
    "broadcast": "10.255.255.255",
    "mascara": "255.0.0.0",
    "cidr": "/8",
    "hosts_uteis": 16777214,
    "classe": "A",
    "tipo": "Privada (RFC 1918)"
  }
}
```

### Exemplo 2: Resolução DNS com Tratamento de Erro

```bash
# Request
curl "http://localhost:5000/api/analisar/dominio?hostname=google.com"

# Response (Sucesso)
{
  "modo": "dominio",
  "resultado": {
    "hostname": "google.com",
    "ip": "142.251.41.14",
    "pais": "United States",
    "tempo_resolucao_ms": 145
  }
}

# Response (Erro - Timeout)
{
  "erro": "Timeout ao resolver DNS...",
  "status": "dns_timeout"
}
```

### Exemplo 3: VLSM para 3 Localidades

```bash
curl -X POST "http://localhost:5000/api/resolver/vlsm" \
  -H "Content-Type: application/json" \
  -d '{
    "rede_base": "172.16.0.0/16",
    "localidades": [
      {"nome": "SP", "hosts_necessarios": 1000},
      {"nome": "RJ", "hosts_necessarios": 500},
      {"nome": "MG", "hosts_necessarios": 250}
    ],
    "topology_type": "mesh",
    "prefixo_wan": 30
  }'

# Response (Simplificado)
{
  "resultado": {
    "vlans_lan": [
      {"localidade": "SP", "rede": "172.16.0.0/22", "hosts": 1022},
      {"localidade": "RJ", "rede": "172.16.4.0/23", "hosts": 510},
      {"localidade": "MG", "rede": "172.16.6.0/24", "hosts": 254}
    ],
    "links_wan": [
      {"enlace": "SP-RJ", "rede": "172.16.8.0/30"},
      {"enlace": "SP-MG", "rede": "172.16.8.4/30"},
      {"enlace": "RJ-MG", "rede": "172.16.8.8/30"}
    ]
  }
}
```

---

## 🔗 RECURSOS RELACIONADOS

- [README.md](README.md) — Visão geral do projeto
- [DEVELOPMENT.md](DEVELOPMENT.md) — Guia para desenvolvedores
- [TESTING.md](TESTING.md) — Como testar
- [FAQ.md](FAQ.md) — Perguntas frequentes

---

**Última atualização:** 08/05/2026  
**Versão:** 1.0 - Inicial
