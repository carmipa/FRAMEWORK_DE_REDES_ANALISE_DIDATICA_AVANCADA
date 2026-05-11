"""Testes de unidade do planejamento VLSM/WAN (sem HTTP)."""

import unittest

from backend.core.exceptions import EntradaInvalidaError
from backend.resolucao.vlsm.vlsm_service import solve_network_problem


class TestSolveNetworkProblemUnit(unittest.TestCase):
    """Cobertura direta de solve_network_problem e CLI EIGRP gerada."""

    def test_cenario_prova_172_19_quatro_sites_eigrp_71(self):
        """Enunciado-tipo: 172.19.0.0/16, quatro localidades, anel, WAN /30, AS 71."""
        locs = [
            {"name": "Matriz", "hosts": "800"},
            {"name": "Filial I", "hosts": "700"},
            {"name": "Filial II", "hosts": "600"},
            {"name": "CPD", "hosts": "550"},
        ]
        s = solve_network_problem(
            "172.19.0.0/16",
            locs,
            topology_type="ring",
            wan_prefix=30,
            eigrp_as=71,
        )
        self.assertEqual(s["base_network"], "172.19.0.0/16")
        self.assertEqual(s["base_network_prefix"], 16)
        self.assertEqual(s["eigrp_as"], 71)
        self.assertEqual(s["wan_prefix"], 30)
        self.assertEqual(s["topology_type"], "ring")
        self.assertEqual(s["total_locations"], 4)
        self.assertEqual(s["total_hosts_requested"], 800 + 700 + 600 + 550)
        self.assertEqual(len(s["lan_blocks"]), 4)
        self.assertEqual(len(s["wan_links"]), 4)

        names = {b["location_name"] for b in s["lan_blocks"]}
        self.assertEqual(names, {"Matriz", "Filial I", "Filial II", "CPD"})

        cli_matriz = s["router_commands"]["Matriz"]
        self.assertIn("router eigrp 71", cli_matriz)
        self.assertIn("no auto-summary", cli_matriz)
        self.assertNotIn("router rip", cli_matriz)
        self.assertIn("network", cli_matriz)
        self.assertIn("show ip route eigrp", cli_matriz)

    def test_eigrp_as_string_e_customizado(self):
        """AS informado como string numérica e diferente do padrão 71."""
        locs = [{"name": "A", "hosts": "50"}, {"name": "B", "hosts": "50"}]
        s = solve_network_problem(
            "10.0.0.0/24",
            locs,
            topology_type="ring",
            wan_prefix=30,
            eigrp_as="100",
        )
        self.assertEqual(s["eigrp_as"], 100)
        cli = s["router_commands"]["A"]
        self.assertIn("router eigrp 100", cli)

    def test_eigrp_as_invalido_zero(self):
        locs = [{"name": "X", "hosts": "10"}]
        with self.assertRaises(EntradaInvalidaError) as ctx:
            solve_network_problem("192.168.0.0/24", locs, eigrp_as=0)
        self.assertIn("65535", str(ctx.exception).lower())

    def test_eigrp_as_invalido_nao_numerico(self):
        locs = [{"name": "X", "hosts": "10"}]
        with self.assertRaises(EntradaInvalidaError) as ctx:
            solve_network_problem("192.168.0.0/24", locs, eigrp_as="xyz")
        self.assertIn("eigrp", str(ctx.exception).lower())

    def test_mesh_quatro_pontos_num_links_wan(self):
        """Malha completa com 4 localidades => 6 links WAN."""
        locs = [
            {"name": "M1", "hosts": "100"},
            {"name": "M2", "hosts": "100"},
            {"name": "M3", "hosts": "100"},
            {"name": "M4", "hosts": "100"},
        ]
        s = solve_network_problem(
            "172.20.0.0/16",
            locs,
            topology_type="mesh",
            wan_prefix=30,
            eigrp_as=71,
        )
        self.assertEqual(len(s["wan_links"]), 6)
        self.assertEqual(s["topology_type"], "mesh")

    def test_diagrama_mermaid_inclui_switch_e_dois_pcs_por_localidade(self):
        locs = [
            {"name": "Matriz", "hosts": "50"},
            {"name": "Filial", "hosts": "40"},
        ]
        s = solve_network_problem("192.168.0.0/24", locs, topology_type="ring")
        m = s["topology_mermaid"]
        self.assertIn("subgraph LAN_1", m)
        self.assertIn("Switch", m)
        self.assertIn("PC teste 1", m)
        self.assertIn("PC teste 2", m)
        self.assertIn("SW_1 --- PC_1A", m)
        td = s["topology_details"]
        self.assertIn("PC_1A", td)
        self.assertEqual(td["PC_1A"]["type"], "host")
        self.assertEqual(td["SW_1"]["type"], "switch")

    def test_tabelas_packet_tracer_por_roteador(self):
        locs = [
            {"name": "Matriz", "hosts": "100"},
            {"name": "Filial", "hosts": "80"},
        ]
        s = solve_network_problem("172.16.0.0/22", locs, topology_type="ring")
        pt = s["pt_router_tables"]
        self.assertEqual(len(pt), 2)
        m = next(b for b in pt if b["location_name"] == "Matriz")
        self.assertEqual(m["router_name"][:2], "R-")
        rows = m["rows"]
        self.assertEqual(rows[0]["interface"], "GigabitEthernet0/0")
        self.assertEqual(rows[0]["role"], "LAN")
        self.assertTrue(any(r["role"] == "WAN" for r in rows))


if __name__ == "__main__":
    unittest.main()
