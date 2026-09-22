import pytest
from scripts.cipher_toolkit import decode_hex, decode_base64, decode_rot13, bruteforce_caesar, bruteforce_single_byte_xor, identify_hash_type, extract_flag

def test_decode_hex():
    hex_str = "666c61677b6865785f746573747d"
    assert decode_hex(hex_str) == "flag{hex_test}"

def test_decode_base64():
    b64_str = "ZmxhZ3tiYXNlNjRfdGVzdH0="
    assert decode_base64(b64_str) == "flag{base64_test}"

def test_decode_rot13():
    rot_str = "synt{ebg13_grfg}"
    assert decode_rot13(rot_str) == "flag{rot13_test}"

def test_bruteforce_caesar():
    cipher = "iodj{fdhvdu_whvw}" # shift 3 for flag{caesar_test}
    shifts = bruteforce_caesar(cipher)
    found = [text for shift, text in shifts if "flag{caesar_test}" in text]
    assert len(found) == 1

def test_single_byte_xor():
    target = b"flag{xor_test}"
    key = 0x42
    ciphertext = bytes([b ^ key for b in target])
    candidates = bruteforce_single_byte_xor(ciphertext)
    assert any("flag{xor_test}" in text for k, score, text in candidates)

def test_identify_hash():
    md5_hash = "5d41402abc4b2a76b9719d911017c592"
    assert "MD5" in identify_hash_type(md5_hash)
    
    sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert "SHA-256" in identify_hash_type(sha256_hash)

def test_extract_flag():
    text = "Congratulations! Here is your token: flag{s3cur1ty_pr0_fl4g} enjoy!"
    flags = extract_flag(text)
    assert flags == ["flag{s3cur1ty_pr0_fl4g}"]
