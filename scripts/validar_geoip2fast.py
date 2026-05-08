"""Validação rápida do motor GeoIP (geoip2fast + contrato legado)."""

import pathlib
import sys

_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from backend.analise.geo.geo_lookup_service import lookup_regiao_geografica


def main() -> int:
    casos = [
        ("8.8.8.8", "US", False),
        ("1.1.1.1", "AU", False),
        ("177.71.128.0", "BR", False),
        ("200.148.0.0", "BR", False),
        ("192.168.1.1", "", True),
        ("10.0.0.1", "", True),
        ("127.0.0.1", "", True),
        ("100.64.0.1", "", True),
        ("::1", "", True),
        ("2804:14d::", "BR", False),
    ]
    print("Testando geoip2fast / lookup_regiao_geografica...")
    falhas = 0
    for ip, pais_esperado, reservado_esperado in casos:
        r = lookup_regiao_geografica(ip)
        reservado = bool(r.get("reservado"))
        cc = (r.get("pais_codigo") or r.get("codigo_pais") or "").strip()
        ok_reservado = reservado == reservado_esperado
        ok_pais = (pais_esperado == "" or cc == pais_esperado)
        ok = ok_reservado and ok_pais
        if not ok:
            falhas += 1
        status = "OK" if ok else "FALHOU"
        fonte = r.get("fonte", "")
        print(
            f"  [{status}] {ip:20s} -> {cc!s:5s} "
            f"reservado={reservado} fonte={fonte!s}"
        )
    if falhas:
        print(f"\n{falhas} caso(s) falharam.")
        return 1
    print("\nTodos os casos [OK].")
    return 0


if __name__ == "__main__":
    sys.exit(main())
