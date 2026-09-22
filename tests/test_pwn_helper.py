import pytest
from scripts.pwn_helper import (
    p32,
    u32,
    p64,
    u64,
    cyclic,
    cyclic_find,
    parse_elf_header,
    generate_gdb_init
)


def test_packing_unpacking_32():
    val = 0xdeadbeef
    packed = p32(val)
    assert packed == b'\xef\xbe\xad\xde'
    assert u32(packed) == val


def test_packing_unpacking_64():
    val = 0x1122334455667788
    packed = p64(val)
    assert packed == b'\x88\x77\x66\x55\x44\x33\x22\x11'
    assert u64(packed) == val


def test_cyclic_generation_and_find():
    pattern = cyclic(64)
    assert len(pattern) == 64
    assert pattern.startswith(b'aaaaaaab')

    # Find offset by byte string
    offset_b = cyclic_find(b'aaab')
    assert offset_b == 4

    # Find offset by unpacked 32-bit little-endian integer (0x62616161 = 'aaab')
    offset_int = cyclic_find(0x62616161)
    assert offset_int == 4


def test_elf_header_parser():
    # Mock minimal 64-bit little-endian ELF header
    # e_ident: 7f 45 4c 46 (ELF), 02 (64-bit), 01 (little endian), 01 (version)
    mock_elf = bytearray(64)
    mock_elf[0:4] = b'\x7fELF'
    mock_elf[4] = 2  # 64-bit
    mock_elf[5] = 1  # Little endian
    # e_type = 2 (EXEC), e_machine = 62 (x86-64), e_version = 1, e_entry = 0x401000
    mock_elf[16:18] = b'\x02\x00'
    mock_elf[18:20] = b'\x3e\x00'
    mock_elf[24:32] = b'\x00\x10\x40\x00\x00\x00\x00\x00'

    parsed = parse_elf_header(bytes(mock_elf))
    assert parsed is not None
    assert parsed["format"] == "ELF64"
    assert parsed["arch"] == "64-bit"
    assert parsed["endian"] == "little"
    assert parsed["entrypoint"] == "0x401000"


def test_gdb_script_generator():
    script = generate_gdb_init(breakpoints=["main", "0x401122"], binary="test_bin")
    assert "file test_bin" in script
    assert "break *main" in script
    assert "break *0x401122" in script
    assert "run" in script
