import unittest
import zipfile
from io import BytesIO
from unittest.mock import patch

from app import create_app
from backend.analise.ipv4_service import core_mascara, enunciado_prova_intervalos, tabela_referencia_subredes


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_cidr_31(self):
        res = self.client.post("/", data={"modo": "cidr", "ip": "10.0.0.0", "cidr": "31"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("/ 31", html)
        self.assertIn("RFC 3021", html)

    def test_cidr_32(self):
        res = self.client.post("/", data={"modo": "cidr", "ip": "10.0.0.1", "cidr": "32"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("/ 32", html)

    def test_cidr_campo_ip_com_mascara_usa_modo_subrede_nao_classe_e(self):
        """255.255.192.0 no campo IP não é host — não deve aparecer observação classe E pelo 1º octeto."""
        res = self.client.post(
            "/",
            data={"modo": "cidr", "ip": "255.255.192.0", "cidr": "18"},
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        h = html.lower()
        self.assertIn("sub-rede", h)
        self.assertIn("lógica:", h)
        self.assertIn("classe-card-unificada cv-b", html.replace("\n", ""))
        self.assertNotIn("faixa e", h)
        self.assertNotIn("1º octeto: 255", html)

    def test_cidr_sem_barra_infere_pelo_ip(self):
        """Aba CIDR: campo numérico vazio → inferência classful pelo 1º octeto."""
        res = self.client.post("/", data={"modo": "cidr", "ip": "10.5.5.5", "cidr": ""})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("inferido", html.lower())
        self.assertIn("/8", html)
        res2 = self.client.post("/", data={"modo": "cidr", "ip": "200.1.1.1", "cidr": ""})
        self.assertEqual(res2.status_code, 200)
        self.assertIn("/24", res2.get_data(as_text=True))

    def test_broadcast_alert(self):
        res = self.client.post("/", data={"modo": "cidr", "ip": "192.168.1.255", "cidr": "24"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Aviso Smurf Attack", html)

    def test_dominio_invalido(self):
        res = self.client.post("/", data={"modo": "dominio", "ip": "dominio@@invalido"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Domínio/hostname inválido", html)

    @patch(
        "backend.analise.dominio.dominio_service.resolver_dns_com_cache",
        return_value="93.184.216.34",
    )
    def test_dominio_url_completa(self, dns_mock):
        res = self.client.post("/", data={"modo": "dominio", "ip": "https://example.com/path?a=1", "cidr": "24"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        dns_mock.assert_called_once_with("example.com")
        self.assertIn("Domínio &#39;example.com&#39; resolvido para 93.184.216.34", html)

    def test_wildcard_invalida(self):
        res = self.client.post("/", data={"modo": "wildcard", "ip": "172.16.8.8", "wildcard_mask": "0.0.255.0"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Wildcard inválida", html)

    def test_regua_count_alto(self):
        res = self.client.post("/", data={"modo": "cidr", "ip": "10.0.0.0", "cidr": "24", "regua_count": "100"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("RÉGUA DE SUB-REDES (próximas 100)", html)

    def test_enunciado_prova_mascara_255_255_224_0(self):
        """Exercício típico: só máscara → /19, 8 intervalos de 32, 8192/8190 por bloco."""
        o, _ = tabela_referencia_subredes(19)
        e = enunciado_prova_intervalos(19, 32, 8192, 8190, o)
        self.assertEqual(e["qtde_intervalos"], 8)
        self.assertEqual(e["variacao"], 32)
        self.assertEqual(e["octeto_referencia"], 3)
        self.assertIn("8 intervalos que variam de 32 em 32", e["frase_estilo_quadro"])
        self.assertIn("8192", e["frase_estilo_quadro"])
        self.assertIn("2^3 = 8", e["linha_potencias_quadro"])
        self.assertIn("2^5 = 32", e["linha_potencias_quadro"])
        self.assertIn("2^13 = 8192", e["linha_potencias_quadro"])
        e30 = enunciado_prova_intervalos(30, 4, 4, 2, 4)
        self.assertIn("2^6 = 64", e30["linha_potencias_quadro"])
        self.assertIn("2^2 = 4", e30["linha_potencias_quadro"])
        res = self.client.post(
            "/",
            data={"modo": "mask", "mask_decimal": "255.255.224.0"},
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Resposta tipo prova", html)
        self.assertIn("Qtde de intervalos", html)
        self.assertIn("enunciado-prova-mascara", html)
        self.assertIn("Lógica: sub-rede", html)

    def test_mask_mascara_no_campo_ip_vence_conflito_18_nao_4(self):
        """POST com ip+mask (ex.: replay API): 255.255.192.0 + 240.0.0.0 → prioriza /18, não /4."""
        res = self.client.post(
            "/",
            data={
                "modo": "mask",
                "ip": "255.255.192.0",
                "mask_decimal": "240.0.0.0",
            },
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("/18", html)
        self.assertNotIn("/4 · 240.0.0.0", html)
        self.assertIn("Conflito", html)

    def test_mask_aba_so_campo_mascara_decimal_255_255_192_0(self):
        """Formulário da aba Máscara: apenas máscara decimal."""
        res = self.client.post(
            "/",
            data={"modo": "mask", "mask_decimal": "255.255.192.0"},
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("/18", html)
        self.assertIn("só máscara", html.lower())

    def test_modo_host_nao_mostra_enunciado_prova_subrede(self):
        """Com IP + máscara usa lógica de host — não deve repetir o quadro tipo prova só-de-sub-rede."""
        res = self.client.post("/", data={"modo": "cidr", "ip": "172.19.0.10", "cidr": "19"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("enunciado-prova-mascara", html)
        self.assertIn("Lógica: host", html)

    def test_abertura_intervalos_dinamica(self):
        res = self.client.post("/", data={"modo": "cidr", "ip": "172.19.0.0", "cidr": "20"})
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("ABERTURA DOS INTERVALOS", html)
        self.assertIn("PASSO A PASSO DO CÁLCULO", html)
        self.assertIn("🧭 Classe/faixa", html)
        self.assertIn("📏 Máscara", html)
        self.assertIn("LINHA DO TEMPO DO BLOCO", html)
        self.assertIn("16 intervalos variam de 16 em 16", html)
        self.assertIn("172.19.0.0 até 172.19.15.255/20", html)

    def test_pulo_em_fronteiras_cidr(self):
        self.assertEqual(core_mascara(24)["pulo"], 1)
        self.assertEqual(core_mascara(16)["pulo"], 1)
        self.assertEqual(core_mascara(8)["pulo"], 1)
        self.assertEqual(core_mascara(30)["pulo"], 4)

    def test_modo_mask_ignora_ip_nao_numerico(self):
        res = self.client.post(
            "/",
            data={"modo": "mask", "ip": "nao-resolver.local", "mask_decimal": "255.255.255.0"},
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("Não foi possível resolver o domínio informado", html)
        self.assertIn("IP inválido. Use formato x.x.x.x.", html)
        self.assertIn("Por que aconteceu", html)
        self.assertIn("Como corrigir", html)

    def test_comparador_cidr_lado_a_lado(self):
        res = self.client.post(
            "/",
            data={
                "modo": "comparador",
                "ip": "172.19.0.10",
                "comparador_cidr_a": "20",
                "comparador_cidr_b": "24",
            },
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("ÁREA DO COMPARADOR CIDR (mesmo IP)", html)
        self.assertIn("/20", html)
        self.assertIn("/24", html)

    def test_pagina_resolucao_problemas_get(self):
        res = self.client.get("/resolucao-problemas")
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Resolução de Problemas de Redes", html)
        self.assertIn("Cenário de entrada", html)

    def test_resolucao_get_formulario_em_branco_sem_demo(self):
        res = self.client.get("/resolucao-problemas")
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertNotIn('value="172.21.0.0"', html)

    def test_resolucao_get_demo_preenche_exemplo(self):
        res = self.client.get("/resolucao-problemas?demo=1")
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn('value="172.21.0.0"', html)

    def test_pagina_resolucao_problemas_post(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "loc_name": ["Matriz", "Filial I", "Filial II"],
                "loc_hosts": ["420", "400", "380"],
            },
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("LANs (VLSM)", html)
        self.assertIn("Links WAN /30", html)
        self.assertIn("CLI MATRIZ", html)

    def test_pagina_resolucao_problemas_post_com_4_localidades(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "loc_name": ["Matriz", "Filial I", "Filial II", "Filial III"],
                "loc_hosts": ["420", "400", "380", "120"],
            },
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Filial III", html)
        self.assertIn("Localidades:", html)
        self.assertIn("CLI FILIAL III", html)

    def test_pagina_resolucao_problemas_topologia_mesh(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "base_network": "172.21.0.0/16",
                "topology_type": "mesh",
                "loc_name": ["Matriz", "Filial I", "Filial II"],
                "loc_hosts": ["420", "400", "380"],
            },
        )
        html = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("Topologia WAN:", html)
        self.assertIn("MESH", html)

    def test_exportar_lab_packet_tracer_txt(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "action_type": "export",
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "loc_name": ["Matriz", "Filial I", "Filial II"],
                "loc_hosts": ["420", "400", "380"],
            },
        )
        body = res.get_data(as_text=True)
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/plain", res.content_type)
        self.assertIn("attachment;", res.headers.get("Content-Disposition", ""))
        self.assertIn("SCRIPT DE PROVISIONAMENTO", body)
        self.assertIn("ROTEADOR: MATRIZ", body)
        self.assertIn("enable", body)
        self.assertIn("configure terminal", body)
        self.assertIn("logging synchronous", body)
        self.assertIn("description LAN_MATRIZ", body)
        self.assertIn("description LINK_PARA_FILIAL_I", body)
        self.assertIn("router eigrp 71", body)
        self.assertIn("show ip route eigrp", body)
        self.assertIn("2911", body)
        self.assertIn("2960", body)
        self.assertIn("! AS EIGRP: 71", body)
        self.assertIn("! Prefixo WAN: /30", body)
        self.assertIn("enable password cisco", body)
        self.assertIn("line vty 0 4", body)
        self.assertIn("clock rate 64000", body)

    def test_exportar_lab_packet_tracer_zip(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "action_type": "export_zip",
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "loc_name": ["Matriz", "Filial I", "Filial II"],
                "loc_hosts": ["420", "400", "380"],
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("application/zip", res.content_type)
        self.assertIn("attachment;", res.headers.get("Content-Disposition", ""))
        archive = zipfile.ZipFile(BytesIO(res.data))
        names = set(archive.namelist())
        self.assertIn("GUIA_MONTAGEM_PACKET_TRACER.txt", names)
        self.assertIn("config_packet_tracer_consolidado.txt", names)
        self.assertIn("LAB_TOPOLOGY.mermaid", names)
        self.assertIn("README_LAB.txt", names)
        self.assertIn("configs_individuais/R-MATRIZ.txt", names)
        readme = archive.read("README_LAB.txt").decode("utf-8")
        self.assertIn("GUIA_MONTAGEM_PACKET_TRACER.txt", readme)
        self.assertIn("INSTRUCOES DE USO DO LABORATORIO", readme)
        guia = archive.read("GUIA_MONTAGEM_PACKET_TRACER.txt").decode("utf-8")
        self.assertIn("GUIA DE MONTAGEM", guia)
        consolidated = archive.read("config_packet_tracer_consolidado.txt").decode("utf-8")
        self.assertIn("router eigrp 71", consolidated)
        self.assertIn("SCRIPT DE PROVISIONAMENTO", consolidated)

    def test_informacoes_pagina_apenas_geo(self):
        res = self.client.get("/informacoes")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Região geográfica", html)
        self.assertNotIn("Conteúdo didático", html)

    def test_api_informacoes_geo_localhost_sem_chamada_externa(self):
        res = self.client.get("/api/informacoes/geo")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, dict)
        self.assertFalse(data.get("ok"))
        self.assertEqual(data.get("motivo"), "private_or_local")
        self.assertEqual(data.get("modo"), "ligacao")
        self.assertIn("consultado", data)

    def test_api_informacoes_geo_ip_invalido(self):
        res = self.client.get("/api/informacoes/geo?ip=nao-e-ip")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertFalse(data.get("ok"))
        self.assertEqual(data.get("motivo"), "invalid")

    def test_historico_paginacao_renderiza_total_e_navegacao(self):
        for i in range(5):
            self.client.post("/", data={"modo": "cidr", "ip": f"10.77.{i}.10", "cidr": "24"})
        res = self.client.get("/?tab=cidr&history_limit=2&history_page=1")
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Histórico de Consultas", html)
        self.assertIn("Página 1 de", html)
        self.assertIn("Próxima", html)
        self.assertIn("Itens por página", html)
        res_p2 = self.client.get("/?tab=cidr&history_limit=2&history_page=2")
        self.assertEqual(res_p2.status_code, 200)
        self.assertIn("Página 2 de", res_p2.get_data(as_text=True))

    def test_historico_nao_renderiza_nas_abas_geo_e_catalogos(self):
        for tab in ("geo", "portas", "protocolos"):
            res = self.client.get(f"/?tab={tab}&history_limit=2&history_page=1")
            self.assertEqual(res.status_code, 200)
            html = res.get_data(as_text=True)
            self.assertNotIn("Histórico de Consultas", html)
        geo_html = self.client.get("/?tab=geo").get_data(as_text=True)
        self.assertIn("Histórico GeoIP", geo_html)
        geo_html = self.client.get("/?tab=geo").get_data(as_text=True)
        self.assertIn("Histórico GeoIP", geo_html)

    @patch("backend.analise.geo.geo_service.lookup_regiao_geografica")
    def test_api_informacoes_geo_prefere_ipv4_global_do_xff(self, mock_geo):
        mock_geo.return_value = {
            "ok": True,
            "ip": "8.8.8.8",
            "pais": "United States",
            "codigo_pais": "US",
            "regiao": "California",
        }
        res = self.client.get(
            "/api/informacoes/geo",
            headers={"X-Forwarded-For": "fd00::1, 2001:4860:4860::8888, 8.8.8.8"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data.get("consultado"), "8.8.8.8")
        self.assertEqual(data.get("cliente_ip"), "8.8.8.8")
        mock_geo.assert_called_once_with("8.8.8.8")

    @patch("backend.analise.geo.geo_service.lookup_regiao_geografica")
    def test_api_informacoes_geo_ip_manual_publico(self, mock_geo):
        mock_geo.return_value = {
            "ok": True,
            "ip": "8.8.8.8",
            "pais": "United States",
            "codigo_pais": "US",
            "regiao": "California",
            "cidade": "Mountain View",
            "lat": 37.0,
            "lon": -122.0,
            "isp": "Google",
        }
        res = self.client.get("/api/informacoes/geo?ip=8.8.8.8")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("modo"), "manual")
        self.assertEqual(data.get("consultado"), "8.8.8.8")
        mock_geo.assert_called_once_with("8.8.8.8")

    @patch("backend.analise.geo.geo_service.lookup_regiao_geografica")
    def test_api_informacoes_geo_registra_em_historico_geo(self, mock_geo):
        mock_geo.return_value = {
            "ok": True,
            "ip": "1.1.1.1",
            "pais": "Australia",
            "codigo_pais": "AU",
            "regiao": "Queensland",
        }
        res = self.client.get("/api/informacoes/geo?ip=1.1.1.1")
        self.assertEqual(res.status_code, 200)
        hist = self.client.get("/history").get_json()
        self.assertIsInstance(hist, dict)
        items = hist.get("items", [])
        self.assertTrue(any((it.get("modo") == "geo" and it.get("ip_entrada") == "1.1.1.1") for it in items))


if __name__ == "__main__":
    unittest.main()
