# Documentação Técnica Atualizada - Framework de Redes

## 1) Objetivo do projeto

Aplicação web didática em Flask para estudo de redes de computadores, com foco em:

- análise IPv4/IPv6 e fundamentos de subnetting;
- catálogos de portas e protocolos;
- geolocalização de IP;
- resolução de cenários completos com VLSM + WAN (ring/mesh);
- geração de artefatos de laboratório (TXT/ZIP) e relatório final de entrega.

---

## 2) Stack e dependências

- Linguagem: Python 3.12+
- Framework web: Flask
- Testes: pytest + unittest
- Geolocalização: `geoip2fast`
- Containerização: Docker / Docker Compose

Dependências diretas em `requirements.txt`:

- `flask`
- `colorama>=0.4.6`
- `pytest`
- `geoip2fast>=1.2.2`

---

## 3) Arquitetura da aplicação

### 3.1 Ponto de entrada

- `app.py` concentra o factory `create_app()`
- registra todos os blueprints;
- aplica `ProxyFix` quando `APP_BEHIND_PROXY=true`;
- define `before_request` e `after_request` para logs com `request_id`;
- possui handler global para exceções inesperadas.

### 3.2 Camadas principais

- `backend/web/`: views gerais (`/`, `/informacoes`, `/api/informacoes/geo`, `/icone.png`);
- `backend/analise/`: modos didáticos (CIDR, máscara, wildcard, auto CIDR, domínio, IPv6, comparador, geo, catálogos);
- `backend/resolucao/`: módulo de resolução de problemas (VLSM/WAN) e exportação;
- `backend/suporte/`: histórico, GRC e auditoria;
- `backend/core/`: logging, helpers e exceções base.

### 3.3 Front-end (server-rendered)

- Templates Jinja em `templates/`;
- componentes reutilizados em `templates/shared/partials/` e `templates/analise/partials/`;
- estilos em `static/css/app.css`;
- script de UI para geo em `static/js/geo_report.js`.

---

## 4) Funcionalidades por módulo

## 4.1 Análise didática (`/`)

Modos suportados no fluxo principal:

- `cidr`: cálculo por IP + prefixo;
- `mask`: análise por máscara decimal;
- `wildcard`: análise por wildcard mask;
- `autoip`: inferência de CIDR por IP;
- `dominio`: resolução de domínio/hostname para IP e análise;
- `ipv6`: interpretação didática básica;
- `comparador`: comparação lado a lado de dois CIDRs sobre o mesmo IP;
- `geo`: bloco geo integrado no front;
- `portas` e `protocolos`: catálogos técnicos para consulta.

Também inclui:

- histórico paginado de consultas;
- mensagens didáticas de erro;
- trilha de cálculo (wizard/timeline);
- classificação de apoio em GRC.

## 4.2 Resolução de problemas (`/resolucao-problemas`)

Entrega um planejador completo de cenário de rede:

- entrada da rede base (IPv4);
- múltiplas localidades e demanda de hosts;
- escolha de topologia WAN (`ring`/`mesh`);
- prefixo WAN configurável (tipicamente `/30`);
- alocação VLSM LAN + links WAN;
- geração de comandos CLI Cisco por roteador;
- geração de topologia Mermaid;
- exportações para laboratório e documentação.

## 4.3 Exportações e histórico

- `GET /export/json`: exporta histórico em JSON;
- `GET /export/pdf`: rota de exportação PDF;
- `GET /history`: retorna histórico;
- `POST /history/catalog`: registra consultas dos catálogos (portas/protocolos).

---

## 5) Rotas HTTP mapeadas

Rotas principais identificadas no código:

- `GET|POST /` -> home com todos os modos de análise;
- `GET /informacoes` -> página de informações e região geográfica;
- `GET /api/informacoes/geo` -> API JSON de geolocalização;
- `GET /icone.png` -> ícone do projeto;
- `GET|POST /resolucao-problemas` -> resolução VLSM/WAN + exportações via `action_type`;
- `GET /export/json` -> exportação JSON;
- `GET /export/pdf` -> exportação PDF;
- `GET /history` -> consulta histórico;
- `POST /history/catalog` -> histórico para catálogos.

---

## 6) Configuração por ambiente

Variáveis importantes (arquivo `backend/config.py` e compose):

- `APP_HOST` (default `127.0.0.1`)
- `APP_PORT` (default `5000`)
- `APP_DEBUG` (default `true`)
- `APP_OPEN_BROWSER` (default `true`)
- `APP_BEHIND_PROXY` (default `false`)
- `APP_MAX_HISTORY` (default `60`)
- `DNS_CACHE_TTL_SECONDS` (default `180`)
- `DNS_RESOLVE_TIMEOUT_SECONDS` (default `3.0`)

Observações de execução em container:

- `docker-compose.yml` expõe `127.0.0.1:5000:5000`;
- usa rede externa `nginx-proxy-network`;
- `Dockerfile` executa `python app.py`.

---

## 7) Testes e cobertura funcional validada

A suíte em `tests/` cobre, entre outros pontos:

- modos de análise (`cidr`, `mask`, `wildcard`, `autoip`, `ipv6`, `comparador`, `dominio`);
- comportamentos de borda (`/31`, `/32`, conflitos de máscara, entradas inválidas);
- rotas de resolução VLSM com diferentes localidades/topologias;
- exportações (`txt`, `zip`, `entrega`);
- histórico paginado e histórico de catálogos;
- API de geolocalização e página de informações.

Comando recomendado:

```bash
python -m pytest -q
```

---

## 8) Diretório de pastas e arquivos (exibido em linhas)

Inventário linear do repositório versionado (`git ls-files`):

```text
.dockerignore
.github/workflows/python-app.yml
.gitignore
CONFIG_REDE_PRONTA.txt
Dockerfile
LICENSE
Material_07_Protocolos_roteamento.ppt
README.md
app.py
backend/__init__.py
backend/analise/__init__.py
backend/analise/auto_cidr/__init__.py
backend/analise/auto_cidr/auto_cidr_routes.py
backend/analise/auto_cidr/auto_cidr_service.py
backend/analise/cidr/__init__.py
backend/analise/cidr/cidr_routes.py
backend/analise/cidr/cidr_service.py
backend/analise/cidr_service.py
backend/analise/comparador/__init__.py
backend/analise/comparador/comparador_routes.py
backend/analise/comparador/comparador_service.py
backend/analise/dominio/__init__.py
backend/analise/dominio/dominio_routes.py
backend/analise/dominio/dominio_service.py
backend/analise/dominio_service.py
backend/analise/geo/__init__.py
backend/analise/geo/geo_lookup_service.py
backend/analise/geo/geo_routes.py
backend/analise/geo/geo_service.py
backend/analise/geo_service.py
backend/analise/helpers_web.py
backend/analise/home_web_helpers.py
backend/analise/ipv4_service.py
backend/analise/ipv6/__init__.py
backend/analise/ipv6/ipv6_routes.py
backend/analise/ipv6/ipv6_service.py
backend/analise/ipv6_service.py
backend/analise/mascara/__init__.py
backend/analise/mascara/mascara_routes.py
backend/analise/mascara/mascara_service.py
backend/analise/portas/__init__.py
backend/analise/portas/portas_catalog.py
backend/analise/portas/portas_routes.py
backend/analise/portas/portas_service.py
backend/analise/protocolos/__init__.py
backend/analise/protocolos/protocolos_catalog.py
backend/analise/protocolos/protocolos_routes.py
backend/analise/protocolos/protocolos_service.py
backend/analise/wildcard/__init__.py
backend/analise/wildcard/wildcard_routes.py
backend/analise/wildcard/wildcard_service.py
backend/config.py
backend/core/__init__.py
backend/core/exceptions.py
backend/core/helpers.py
backend/core/logging.py
backend/resolucao/__init__.py
backend/resolucao/export/__init__.py
backend/resolucao/export/export_routes.py
backend/resolucao/export/export_service.py
backend/resolucao/export/export_txt_service.py
backend/resolucao/export/export_zip_service.py
backend/resolucao/export/pdf_service.py
backend/resolucao/vlsm/__init__.py
backend/resolucao/vlsm/vlsm_normalization.py
backend/resolucao/vlsm/vlsm_planning.py
backend/resolucao/vlsm/vlsm_routes.py
backend/resolucao/vlsm/vlsm_service.py
backend/suporte/__init__.py
backend/suporte/audit/__init__.py
backend/suporte/audit/audit_service.py
backend/suporte/audit_service.py
backend/suporte/grc/__init__.py
backend/suporte/grc/grc_service.py
backend/suporte/grc_service.py
backend/suporte/historico/__init__.py
backend/suporte/historico/historico_routes.py
backend/suporte/historico/historico_service.py
backend/suporte/historico_service.py
backend/web/__init__.py
backend/web/app_routes.py
consulta_history.json
docker-compose.dev.yml
docker-compose.yml
icone.png
documentacao/GUIA_REFATORACAO_MAIN.txt
documentacao/nova_regra.txt
requirements.txt
scripts/validar_geoip2fast.py
static/css/app.css
static/js/geo_report.js
templates/analise/index.html
templates/analise/partials/history_box.html
templates/analise/partials/tab_autoip.html
templates/analise/partials/tab_cidr.html
templates/analise/partials/tab_comparador.html
templates/analise/partials/tab_dominio.html
templates/analise/partials/tab_geo.html
templates/analise/partials/tab_ipv6.html
templates/analise/partials/tab_mask.html
templates/analise/partials/tab_portas.html
templates/analise/partials/tab_protocolos.html
templates/analise/partials/tab_wildcard.html
templates/base.html
templates/geo/informacoes.html
templates/index.html
templates/informacoes.html
templates/partials/history_box.html
templates/partials/main_menu.html
templates/partials/project_about.html
templates/partials/project_header.html
templates/partials/site_footer.html
templates/partials/tab_autoip.html
templates/partials/tab_cidr.html
templates/partials/tab_comparador.html
templates/partials/tab_dominio.html
templates/partials/tab_geo.html
templates/partials/tab_ipv6.html
templates/partials/tab_mask.html
templates/partials/tab_portas.html
templates/partials/tab_protocolos.html
templates/partials/tab_wildcard.html
templates/resolucao/resolucao_problemas.html
templates/resolucao_problemas.html
templates/shared/partials/geo_relatorio.html
templates/shared/partials/main_menu.html
templates/shared/partials/project_about.html
templates/shared/partials/project_header.html
templates/shared/partials/site_footer.html
tests/test_app.py
tests/test_cobertura_extra.py
```

---

## 9) Fluxo operacional resumido

1. Usuário seleciona modo e envia formulário na home.
2. Backend valida entrada e roteia para serviço específico.
3. Resultado didático é montado e renderizado no template.
4. Consulta pode ser registrada em histórico.
5. No módulo VLSM, o cenário é calculado e pode gerar exportações.

---

## 10) Situação atual e recomendações de evolução

Pontos fortes atuais:

- separação clara por domínio (`analise`, `resolucao`, `suporte`);
- suíte de testes extensa para fluxos críticos;
- exportações prontas para laboratório e entrega acadêmica;
- logging estruturado com contexto de requisição.

Próximas melhorias sugeridas:

- remover duplicações legadas de templates/parciais quando não usadas;
- adicionar documentação de contrato JSON para `/api/informacoes/geo` e `/history`;
- incluir pipeline de lint/format além dos testes;
- versionar changelog técnico por release.
