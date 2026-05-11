"""Testes adicionais: rotas, exportações e fluxos da UI.

Complementa tests/test_app.py.
"""

import json
import unittest
from unittest.mock import patch

from app import create_app
from backend.web import app_routes
from backend.analise.home_web_helpers import normalizar_hostname_entrada
from backend.analise.portas.portas_service import (
    montar_portas_catalogo_exibicao,
)
from backend.analise.protocolos.protocolos_catalog import PROTOCOLOS_CATALOGO


class TestRotasEExportacoes(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.client = self.app.test_client()

    def test_get_home_200(self):
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        self.assertIn("CIDR", res.get_data(as_text=True))

    def test_get_home_abas_catalogo_e_geo(self):
        for tab in ("portas", "protocolos", "ipv6", "autoip", "geo"):
            res = self.client.get(f"/?tab={tab}")
            self.assertEqual(res.status_code, 200, msg=f"tab={tab}")
            html = res.get_data(as_text=True)
            self.assertIn("CyberNet", html)

    def test_post_ipv6_valido(self):
        res = self.client.post(
            "/",
            data={"modo": "ipv6", "ipv6": "2001:db8::1"},
        )
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("Compactação IPv6", html)
        self.assertIn("2001:db8::1", html)

    def test_post_ipv6_vazio_erro(self):
        res = self.client.post("/", data={"modo": "ipv6", "ipv6": ""})
        self.assertEqual(res.status_code, 200)
        self.assertIn("IPv6", res.get_data(as_text=True))

    def test_post_auto_cidr(self):
        res = self.client.post(
            "/",
            data={"modo": "autoip", "ip": "10.20.30.40"},
        )
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("/8", html)

    def test_post_wildcard_valida(self):
        res = self.client.post(
            "/",
            data={
                "modo": "wildcard",
                "ip": "192.168.1.10",
                "wildcard_mask": "0.0.0.255",
            },
        )
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertIn("/24", html)

    def test_post_comparador_ip_invalido(self):
        res = self.client.post(
            "/",
            data={
                "modo": "comparador",
                "ip": "999.0.0.1",
                "comparador_cidr_a": "24",
                "comparador_cidr_b": "26",
            },
        )
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        h = html.lower()
        self.assertTrue("ip" in h or "inválido" in h or "erro" in h)

    def test_post_cidr_sem_ip(self):
        res = self.client.post(
            "/",
            data={"modo": "cidr", "ip": "", "cidr": "24"},
        )
        self.assertEqual(res.status_code, 200)
        html = res.get_data(as_text=True)
        self.assertTrue(len(html) > 100)

    def test_get_icone_png(self):
        res = self.client.get("/icone.png")
        self.assertEqual(res.status_code, 200)
        self.assertIn("image/png", res.content_type or "")

    def test_export_json(self):
        res = self.client.get("/export/json")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIsInstance(data, dict)
        self.assertIn("history", data)
        self.assertIn("generated_at", data)

    @patch(
        "backend.resolucao.export.export_routes.list_history",
        return_value=[],
    )
    def test_export_pdf_redirect_sem_historico(self, _mock_hist):
        res = self.client.get("/export/pdf", follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn("/", res.headers.get("Location", ""))

    def test_export_entrega_txt(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "action_type": "export_entrega",
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "loc_name": ["Matriz", "Filial I"],
                "loc_hosts": ["200", "150"],
            },
        )
        self.assertEqual(res.status_code, 200)
        self.assertIn("text/plain", res.content_type or "")
        body = res.get_data(as_text=True)
        self.assertIn("DOCUMENTACAO DO CENARIO DE REDE", body)
        self.assertIn("2) LANs (VLSM)", body)
        self.assertIn("router eigrp", body.lower())
        self.assertIn("6) Comandos Cisco CLI por roteador", body)
        self.assertIn("3.1) Interfaces por roteador (Packet Tracer)", body)
        self.assertIn("2911", body)
        self.assertIn("2960", body)
        self.assertIn("AS EIGRP:", body)

    def test_export_entrega_propaga_eigrp_do_formulario(self):
        res = self.client.post(
            "/resolucao-problemas",
            data={
                "action_type": "export_entrega",
                "base_network": "172.21.0.0/16",
                "topology_type": "ring",
                "wan_prefix": "30",
                "eigrp_as": "100",
                "loc_name": ["Matriz", "Filial I"],
                "loc_hosts": ["200", "150"],
            },
        )
        self.assertEqual(res.status_code, 200)
        body = res.get_data(as_text=True)
        self.assertIn("AS EIGRP:            100", body)
        self.assertIn("router eigrp 100", body.lower())

    def test_history_catalog_portas_ok(self):
        res = self.client.post(
            "/history/catalog",
            data=json.dumps({"modo": "portas", "entrada": "443"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertTrue(res.get_json().get("ok"))

    def test_history_catalog_modo_invalido(self):
        res = self.client.post(
            "/history/catalog",
            data=json.dumps({"modo": "cidr", "entrada": "x"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(res.get_json().get("ok"))

    @patch("backend.web.app_routes.lookup_regiao_geografica")
    def test_pagina_informacoes_com_geo_mock(self, mock_geo):
        mock_geo.return_value = {
            "ok": True,
            "ip": "8.8.8.8",
            "pais": "US",
            "regiao": "Test",
        }
        res = self.client.get("/informacoes?ip=8.8.8.8")
        self.assertEqual(res.status_code, 200)
        mock_geo.assert_called()
        self.assertIn("Região", res.get_data(as_text=True))


class TestHelpersPuros(unittest.TestCase):
    def test_normalizar_hostname_url(self):
        self.assertEqual(
            normalizar_hostname_entrada("https://Example.COM/path"),
            "example.com",
        )

    def test_normalizar_hostname_simples(self):
        self.assertEqual(
            normalizar_hostname_entrada("  host.local  "),
            "host.local",
        )

    def test_montar_portas_catalogo_nao_vazio(self):
        cat = montar_portas_catalogo_exibicao()
        self.assertIsInstance(cat, list)
        self.assertGreater(len(cat), 0)

    def test_catalogo_protocolos_roteamento_com_campos_didaticos(self):
        roteamento = [p for p in PROTOCOLOS_CATALOGO if p.get("categoria") == "roteamento"]
        self.assertGreaterEqual(len(roteamento), 6)
        for proto in roteamento:
            self.assertTrue(proto.get("convergencia"))
            self.assertTrue(proto.get("ecmp"))
            self.assertTrue(proto.get("problemas_comuns"))
            self.assertTrue(proto.get("mitigacoes"))
            self.assertTrue(proto.get("caso_uso_real"))
            self.assertTrue(proto.get("diagnostico_comandos"))

    def test_catalogo_protocolos_inclui_bgp_ospf_rip_eigrp(self):
        nomes = {p.get("nome", "") for p in PROTOCOLOS_CATALOGO}
        esperados = {"BGP-4 / eBGP", "OSPFv2", "RIPv2", "EIGRP"}
        self.assertTrue(esperados.issubset(nomes))


class TestAppRoutesHelpers(unittest.TestCase):
    def test_resolve_analysis_mode_fallbacks(self):
        self.assertEqual(
            app_routes._resolve_analysis_mode("", "24", "", "", "", ""),
            "cidr",
        )
        self.assertEqual(
            app_routes._resolve_analysis_mode("", "", "255.255.255.0", "", "", ""),
            "mask",
        )
        self.assertEqual(
            app_routes._resolve_analysis_mode("", "", "", "0.0.0.255", "", ""),
            "wildcard",
        )
        self.assertEqual(
            app_routes._resolve_analysis_mode("", "", "", "", "2001:db8::1", ""),
            "ipv6",
        )
        self.assertEqual(
            app_routes._resolve_analysis_mode("", "", "", "", "", "10.0.0.1"),
            "autoip",
        )

    def test_finalize_home_post_com_erro_gera_texto_didatico(self):
        wizard, timeline, erro_didatico = app_routes._finalize_home_post(
            res=None,
            erro="erro de teste",
            wizard_calculo=[],
            timeline_bloco=None,
            erro_didatico=None,
        )
        self.assertEqual(wizard, [])
        self.assertIsNone(timeline)
        self.assertIsInstance(erro_didatico, dict)
        self.assertIn("causa", erro_didatico)
        self.assertIn("como_corrigir", erro_didatico)

    def test_run_ipv4_cidr_post_processing_detecta_cidr_invalido(self):
        result = app_routes._run_ipv4_cidr_post_processing(
            erro=None,
            cidr_val=40,
            ip_p="10.0.0.1",
            forcar_somente_mascara=False,
            cidr_origem="",
            regua_count=5,
            mode="cidr",
            ip_entrada_original="10.0.0.1",
            cidr_raw="40",
            mask_dec_p="",
            wildcard_p="",
        )
        self.assertIn("CIDR deve estar entre 0 e 32", str(result["erro"]))
        self.assertIn("cidr", result["invalid_fields"])

    @patch("backend.web.app_routes.processar_modo_comparador")
    def test_apply_mode_processing_comparador(self, mock_cmp):
        mock_cmp.return_value = {
            "erro": None,
            "comparador_ip": "10.0.0.10",
            "comparador_cards": [{"cidr": 24}, {"cidr": 26}],
            "invalid_fields": set(),
        }
        invalid_fields = set()
        result = app_routes._apply_mode_processing(
            modo="comparador",
            erro=None,
            ip_p="10.0.0.10",
            ipv6_p="",
            cidr_raw="",
            mask_dec_p="",
            wildcard_p="",
            ip_entrada_original="10.0.0.10",
            comparador_cidr_a_pre="24",
            comparador_cidr_b_pre="26",
            invalid_fields=invalid_fields,
        )
        self.assertTrue(result["comparador_only"])
        self.assertEqual(result["comparador_ip"], "10.0.0.10")
        self.assertEqual(len(result["comparador_cards"]), 2)
        mock_cmp.assert_called_once()


if __name__ == "__main__":
    unittest.main()
