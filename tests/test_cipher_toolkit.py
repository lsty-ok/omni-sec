import pytest
from scripts.cipher_toolkit import (
    decode_hex,
    decode_base64,
    decode_rot13,
    decode_brainfuck,
    bruteforce_caesar,
    bruteforce_single_byte_xor,
    identify_hash_type,
    extract_flag
)


def test_decode_hex():
    data = "666c61677b746573745f666c61677d"
    assert decode_hex(data) == "flag{test_flag}"


def test_decode_base64():
    data = "ZmxhZ3t0ZXN0X2ZsYWd9"
    assert decode_base64(data) == "flag{test_flag}"


def test_decode_rot13():
    data = "synt{grfg_synt}"
    assert decode_rot13(data) == "flag{test_flag}"


def test_decode_brainfuck():
    # 8 * 9 = 72 = 'H' in ASCII
    bf_code = "++++++++[>+++++++++<-]>."
    assert decode_brainfuck(bf_code) == "H"


def test_bruteforce_caesar():
    cipher = "khoor"
    results = bruteforce_caesar(cipher)
    shifts = {shift: text for shift, text in results}
    assert shifts[3] == "hello"


def test_single_byte_xor():
    key = 0x42
    original = b"the quick brown fox jumps over the lazy dog"
    cipher = bytes([b ^ key for b in original])
    candidates = bruteforce_single_byte_xor(cipher)
    assert len(candidates) > 0
    assert candidates[0][0] == key
    assert candidates[0][2] == "the quick brown fox jumps over the lazy dog"


def test_identify_hash_type():
    assert "MD5" in identify_hash_type("5d41402abc4b2a76b9719d911017c592")
    assert "SHA-256" in identify_hash_type("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
    assert "bcrypt" in identify_hash_type("$2a$12$R9h/cIPz0gi.URNNXRkh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW")


def test_extract_flag():
    sample = "Random prefix flag{hidden_flag_123} random suffix"
    extracted = extract_flag(sample)
    assert extracted == ["flag{hidden_flag_123}"]
