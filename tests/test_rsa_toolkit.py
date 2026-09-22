import pytest
from scripts.rsa_toolkit import (
    egcd,
    modinv,
    small_e_attack,
    fermat_factorization,
    wiener_attack,
    common_modulus_attack,
    triage_rsa,
    int_to_bytes
)


def test_egcd_and_modinv():
    g, x, y = egcd(17, 3120)
    assert g == 1
    inv = modinv(17, 3120)
    assert inv is not None
    assert (17 * inv) % 3120 == 1


def test_small_e_attack():
    m = 133742
    e = 3
    c = pow(m, e)
    recovered = small_e_attack(c, e)
    assert recovered == m


def test_fermat_factorization():
    p = 1000003
    q = 1000033
    n = p * q
    factors = fermat_factorization(n)
    assert factors is not None
    assert set(factors) == {p, q}


def test_wiener_attack():
    p = 1373307779
    q = 1391919839
    n = p * q
    phi = (p - 1) * (q - 1)
    d = 179  # Small private exponent
    e = modinv(d, phi)
    assert e is not None
    found_d = wiener_attack(n, e)
    assert found_d == d


def test_common_modulus_attack():
    p = 61
    q = 53
    n = p * q
    e1 = 17
    e2 = 13
    m = 123
    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)
    recovered_m = common_modulus_attack(n, e1, e2, c1, c2)
    assert recovered_m == m


def test_triage_rsa():
    m = 1337
    e = 3
    n = 1000000007
    c = pow(m, e)  # m^3 < n
    res = triage_rsa(n, e, c)
    assert res["m_int"] == m
    assert "Small Exponent" in res["method"]
