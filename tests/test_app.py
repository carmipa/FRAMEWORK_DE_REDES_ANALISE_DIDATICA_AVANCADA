import unittest
from unittest.mock import patch

import main


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


if __name__ == "__main__":
    unittest.main()
