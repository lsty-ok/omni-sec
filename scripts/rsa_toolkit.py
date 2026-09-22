"""
RSA Cryptanalysis and Solver Toolkit for omni-sec.
Inspired by RsaCtfTool: Clean, standalone implementation of common RSA factoring & attack algorithms.
Zero heavy external dependencies (pure standard Python library).
"""

import math
from typing import Optional, Tuple, List


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, y, x = egcd(b % a, a)
    return g, x - (b // a) * y, y


def modinv(a: int, m: int) -> Optional[int]:
    """Modular multiplicative inverse."""
    g, x, _ = egcd(a, m)
    if g != 1:
        return None  # Inverse doesn't exist
    return (x % m + m) % m


def continued_fractions(n: int, d: int) -> List[int]:
    """Returns the continued fraction expansion of n / d."""
    res = []
    while d != 0:
        q = n // d
        res.append(q)
        n, d = d, n - q * d
    return res


def convergents(cf: List[int]) -> List[Tuple[int, int]]:
    """Yields convergents (num, den) from a continued fraction expansion."""
    convs = []
    h_2, h_1 = 0, 1
    k_2, k_1 = 1, 0
    for q in cf:
        h = q * h_1 + h_2
        k = q * k_1 + k_2
        convs.append((h, k))
        h_2, h_1 = h_1, h
        k_2, k_1 = k_1, k
    return convs


def fermat_factorization(n: int, max_iter: int = 200000) -> Optional[Tuple[int, int]]:
    """
    Fermat's Factorization Method.
    Effective when primes p and q are close to each other (|p - q| < n^(1/4)).
    """
    if n % 2 == 0:
        return 2, n // 2

    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iter):
        b2 = a * a - n
        b = math.isqrt(b2)
        if b * b == b2:
            p = a - b
            q = a + b
            if p * q == n and p > 1 and q > 1:
                return p, q
        a += 1
    return None


def wiener_attack(n: int, e: int) -> Optional[int]:
    """
    Wiener's Continued Fraction Attack.
    Effective when private exponent d < (1/3) * n^(1/4).
    Returns private key d if successful.
    """
    cf = continued_fractions(e, n)
    for k, d in convergents(cf):
        if k == 0 or d == 0:
            continue
        # Check if ed - 1 is divisible by k: phi = (ed - 1) // k
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Form quadratic equation: x^2 - (n - phi + 1)x + n = 0
        s = n - phi + 1
        discr = s * s - 4 * n
        if discr >= 0:
            r = math.isqrt(discr)
            if r * r == discr:
                p = (s + r) // 2
                q = (s - r) // 2
                if p * q == n and p > 1:
                    return d
    return None


def small_e_attack(c: int, e: int = 3) -> Optional[int]:
    """
    Small Public Exponent Attack (unpadded / m^e < n).
    Calculates exact e-th integer root of ciphertext c.
    """
    if c <= 0:
        return None
    # Integer e-th root binary search
    low = 1
    high = c
    while low <= high:
        mid = (low + high) // 2
        p = pow(mid, e)
        if p == c:
            return mid
        elif p < c:
            low = mid + 1
        else:
            high = mid - 1
    return None


def common_modulus_attack(n: int, e1: int, e2: int, c1: int, c2: int) -> Optional[int]:
    """
    Common Modulus Attack.
    When two identical messages are encrypted under same n with coprime exponents e1, e2.
    """
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        return None

    if s1 < 0:
        c1 = modinv(c1, n)
        if c1 is None:
            return None
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        if c2 is None:
            return None
        s2 = -s2

    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return m


def int_to_bytes(val: int) -> bytes:
    """Converts a big integer to readable ASCII/UTF-8 bytes."""
    length = (val.bit_length() + 7) // 8
    return val.to_bytes(length, byteorder='big')


def triage_rsa(n: int, e: int, c: int) -> dict:
    """Automated RSA solver triaging multiple attack vectors."""
    results = {
        "method": None,
        "d": None,
        "m_int": None,
        "plaintext": None
    }

    # 1. Try Small e root attack
    m_root = small_e_attack(c, e)
    if m_root is not None:
        results["method"] = "Small Exponent Root Attack (m^e < n)"
        results["m_int"] = m_root
        try:
            results["plaintext"] = int_to_bytes(m_root).decode('utf-8', errors='replace')
        except Exception:
            pass
        return results

    # 2. Try Wiener Attack
    d_wiener = wiener_attack(n, e)
    if d_wiener is not None:
        results["method"] = "Wiener Continued Fraction Attack (Small d)"
        results["d"] = d_wiener
        m = pow(c, d_wiener, n)
        results["m_int"] = m
        try:
            results["plaintext"] = int_to_bytes(m).decode('utf-8', errors='replace')
        except Exception:
            pass
        return results

    # 3. Try Fermat Factorization
    factors = fermat_factorization(n)
    if factors is not None:
        p, q = factors
        phi = (p - 1) * (q - 1)
        d = modinv(e, phi)
        if d is not None:
            results["method"] = f"Fermat Factorization (|p - q| small: p={p}, q={q})"
            results["d"] = d
            m = pow(c, d, n)
            results["m_int"] = m
            try:
                results["plaintext"] = int_to_bytes(m).decode('utf-8', errors='replace')
            except Exception:
                pass
            return results

    return results
