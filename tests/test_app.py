import unittest
from unittest.mock import patch

import main
from backend.services.ipv4_service import core_mascara, enunciado_prova_intervalos, tabela_referencia_subredes


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.client = main.app.test_client()

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

    @patch("main.resolver_dns_com_cache", return_value="93.184.216.34")
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


if __name__ == "__main__":
    unittest.main()
