import unittest
from unittest.mock import patch

import main
from backend.services.ipv4_service import core_mascara


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
