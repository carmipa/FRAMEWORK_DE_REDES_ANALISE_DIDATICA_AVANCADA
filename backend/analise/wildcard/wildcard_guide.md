# 🎯 Por Que a Wildcard É o Inverso da Máscara?

## O Problema na Prática

Você tem uma máscara de subrede: **255.255.255.0**

Em ACLs ou OSPF, essa mesma rede se exprime com wildcard: **0.0.0.255**

**Pergunta:** Por que são inversas?

---

## A Resposta: Perspectivas Opostas

### Máscara de Subrede (Subnet Mask)
Define quais bits são **FIXOS** (parte da rede) e quais **VARIAM** (parte dos hosts).

- Bits em **1** = "Esta parte é **fixa** (rede)"
- Bits em **0** = "Esta parte **varia** (hosts)"

**Exemplo: 255.255.255.0**
```
Decimal:  255    . 255    . 255    . 0
Binário:  11111111 11111111 11111111 00000000
          └──────┬──────┘
          Rede fixa    └──┬──┘
                    Hosts variam
```

**Significado:** "Os primeiros 24 bits são a rede, os últimos 8 bits são hosts"

---

### Wildcard Mask (Máscara Curinga)
Define em quais bits o roteador deve **PRESTAR ATENÇÃO** (bits importantes para ACL/OSPF).

- Bits em **1** = "Este bit **VARIA** (estou atento)"
- Bits em **0** = "Este bit é **IGNORADO** (não me importa)"

**Mesmo exemplo, como wildcard: 0.0.0.255**
```
Decimal:  0      . 0      . 0      . 255
Binário:  00000000 00000000 00000000 11111111
          └──────┬──────┘
          Não me importa  └──┬──┘
                    Estou atento
```

**Significado:** "Não me importa os 3 primeiros octetos, mas os últimos 8 bits são importantes"

---

## Por Que São Opostas? (A Lógica)

| Aspecto | Máscara de Subrede | Wildcard | Motivo |
|---------|-------------------|----------|--------|
| **Bit 1** | "Rede fixa aqui" | "Varia aqui (estou atento)" | ❌ OPOSTO |
| **Bit 0** | "Hosts variam aqui" | "Não me importa (ignoro)" | ❌ OPOSTO |

São como **duas línguas diferentes para o mesmo conceito**:

- **Máscara:** Eu falo em termos de "**O QUE É FIXO**"
- **Wildcard:** Eu falo em termos de "**O QUE VARIA**"

---

## Exemplos Práticos

### Exemplo 1: Rede /24

**Em Máscara de Subrede:**
```
Máscara: 255.255.255.0
Rede: 10.0.0.0/24
Significa: 
  - IP fixo: 10.0.0
  - Hosts: 10.0.0.1 a 10.0.0.254
```

**Em Wildcard (ACL):**
```
Wildcard: 0.0.0.255
ACL: permit ip 10.0.0.0 0.0.0.255 any
Significa:
  - Qualquer IP que comece com 10.0.0.x
  - Onde x pode ser de 0 a 255 (varia)
```

---

### Exemplo 2: Rede /28 (14 hosts)

**Em Máscara de Subrede:**
```
Máscara: 255.255.255.240
Rede: 10.0.0.0/28
Binária: 255.255.255.11110000
Significado: 
  - Primeiros 28 bits = rede (fixos)
  - Últimos 4 bits = hosts (variam)
  - Hosts: 10.0.0.1 a 10.0.0.14
```

**Em Wildcard:**
```
Wildcard: 0.0.0.15
Binária: 0.0.0.00001111
ACL: access-list 1 deny 10.0.0.0 0.0.0.15
Significado:
  - Não me importa os primeiros 28 bits (0s)
  - Mas estou atento aos últimos 4 bits (1s)
  - Corresponde a: 10.0.0.0 até 10.0.0.15
```

---

## Como Converter? (Fórmula)

### Regra: **Wildcard = 255.255.255.255 - Máscara**

Ou bit a bit: **Wildcard = NOT(Máscara)**

#### Exemplos:

**Conversão 1:**
```
Máscara:   255.255.255.240
Inverso:   255.255.255.255
           ──────────────
Wildcard:    0.  0.  0. 15
```

Detalhado no último octeto:
```
240 em binário:   11110000
Inverter (NOT):   00001111 = 15
Resultado: 0.0.0.15 ✓
```

**Conversão 2:**
```
Máscara:   255.255.252.0
Wildcard:    0.  0.  3.255

Terceiro octeto: 252 → NOT → 3 ✓
Quarto octeto:     0 → NOT → 255 ✓
```

---

## Casos de Uso Reais

### ACLs em Cisco (Access Control List)

```cisco
! Negar rede inteira 192.168.1.0/24
access-list 101 deny ip 192.168.1.0 0.0.0.255 any

! Permitir apenas 192.168.1.0/25 (primeira metade)
access-list 101 permit ip 192.168.1.0 0.0.0.127 any

! Negar apenas rede WAN 10.0.4.0/30
access-list 101 deny ip 10.0.4.0 0.0.0.3 any
           ↑         ↑      ↑        ↑
           tipo    IP    máscara  wildcard
```

### OSPF Network Statement

```cisco
! Anunciar LAN 192.168.1.0/24 no OSPF
router ospf 1
  network 192.168.1.0 0.0.0.255 area 0
           ↑            ↑
           IP       wildcard
           
  ! Anunciar WAN 10.0.4.0/30
  network 10.0.4.0 0.0.0.3 area 0
           ↑          ↑
           IP    wildcard (/30 = 4 IPs, wildcard = 3)
```

### RIPv2 Network Statement

```cisco
router rip
  network 172.16.0.0
  ! No RIPv2, usa máscara (não wildcard)
```

---

## Tabela de Referência Rápida

| Prefix | Máscara | Wildcard | Uso |
|--------|---------|----------|-----|
| /24 | 255.255.255.0 | 0.0.0.255 | LAN típica (254 hosts) |
| /25 | 255.255.255.128 | 0.0.0.127 | Meia-LAN (126 hosts) |
| /26 | 255.255.255.192 | 0.0.0.63 | Quarta-LAN (62 hosts) |
| /27 | 255.255.255.224 | 0.0.0.31 | Pequena LAN (30 hosts) |
| /28 | 255.255.255.240 | 0.0.0.15 | Muito pequena (14 hosts) |
| /29 | 255.255.255.248 | 0.0.0.7 | Minúscula (6 hosts) |
| /30 | 255.255.255.252 | 0.0.0.3 | Link WAN (2 hosts) |
| /31 | 255.255.255.254 | 0.0.0.1 | P2P (2 hosts, RFC 3021) |

---

## Resumo e Regra de Ouro

```
┌─────────────────────────────────────────────────────┐
│ MÁSCARA E WILDCARD SÃO INVERSAS                     │
│                                                      │
│ Máscara:   "Quero redes EXATAS"                     │
│            Bits 1 = rede, Bits 0 = hosts            │
│                                                      │
│ Wildcard:  "Quero com ESSA VARIAÇÃO"                │
│            Bits 0 = ignore, Bits 1 = atento         │
│                                                      │
│ Fórmula:   Wildcard = 255.255.255.255 - Máscara     │
│            ou: Wildcard = NOT(Máscara)              │
└─────────────────────────────────────────────────────┘
```

---

## Teste Você Mesmo

**Pergunta 1:** Máscara é 255.255.255.192, qual é a wildcard?
<details>
<summary>Resposta</summary>
255.255.255.192 em binário: 11000000
NOT: 00111111 = 63
Wildcard: 0.0.0.63 ✓
</details>

**Pergunta 2:** Wildcard é 0.0.0.127, qual é a máscara?
<details>
<summary>Resposta</summary>
0.0.0.127 em binário: 01111111
NOT: 10000000 = 128
Máscara: 255.255.255.128 (ou /25) ✓
</details>

**Pergunta 3:** Em uma ACL `10.0.0.0 0.0.0.31`, quantos hosts são afetados?
<details>
<summary>Resposta</summary>
Wildcard 31 = binário 00011111 = 5 bits variam
2^5 = 32 endereços (10.0.0.0 a 10.0.0.31)
Menos network + broadcast = 30 hosts utilizáveis
Resposta: 32 endereços (ou 30 hosts) ✓
</details>

---

**Guia Completo: Por Que Wildcard é Inverso da Máscara**  
Criado: 08/05/2026  
Objetivo: Eliminar confusão sobre o conceito fundamental
