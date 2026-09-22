"""
Binary Exploitation (Pwn) and Triage Helper for omni-sec.
Inspired by pwntools: Packing/unpacking, De Bruijn cyclic pattern generator & finder,
and lightweight ELF/PE header analysis.
Zero heavy external dependencies (pure Python standard library).
"""

import struct
from typing import Union, Optional, Dict, Any, List


def p32(number: int, endianness: str = 'little') -> bytes:
    """Packs a 32-bit integer into bytes."""
    fmt = '<I' if endianness == 'little' else '>I'
    return struct.pack(fmt, number & 0xFFFFFFFF)


def u32(data: bytes, endianness: str = 'little') -> int:
    """Unpacks a 32-bit integer from bytes."""
    fmt = '<I' if endianness == 'little' else '>I'
    if len(data) < 4:
        data = data.ljust(4, b'\x00')
    return struct.unpack(fmt, data[:4])[0]


def p64(number: int, endianness: str = 'little') -> bytes:
    """Packs a 64-bit integer into bytes."""
    fmt = '<Q' if endianness == 'little' else '>Q'
    return struct.pack(fmt, number & 0xFFFFFFFFFFFFFFFF)


def u64(data: bytes, endianness: str = 'little') -> int:
    """Unpacks a 64-bit integer from bytes."""
    fmt = '<Q' if endianness == 'little' else '>Q'
    if len(data) < 8:
        data = data.ljust(8, b'\x00')
    return struct.unpack(fmt, data[:8])[0]


def cyclic(length: int = 100, n: int = 4) -> bytes:
    """
    Generates a unique De Bruijn sequence (cyclic pattern) to easily calculate buffer overflow offsets.
    Equivalent to pwntools cyclic(length).
    """
    charset = b"abcdefghijklmnopqrstuvwxyz"
    pattern = bytearray()
    
    # Generate 4-byte unique sequences: aaaa, aaab, aaac, ...
    for c1 in charset:
        for c2 in charset:
            for c3 in charset:
                for c4 in charset:
                    pattern.extend([c1, c2, c3, c4])
                    if len(pattern) >= length:
                        return bytes(pattern[:length])
    return bytes(pattern[:length])


def cyclic_find(subseq: Union[bytes, str, int], n: int = 4, max_len: int = 4096) -> int:
    """
    Finds the offset of a given substring or hex value inside the cyclic pattern.
    Accepts:
      - bytes: b'laaa'
      - str: "laaa"
      - int: 0x6161616c (unpacked integer from crash register e.g. $eip or $rip)
    """
    if isinstance(subseq, int):
        # Unpack as little-endian 32-bit integer by default
        subseq_bytes = p32(subseq)
    elif isinstance(subseq, str):
        subseq_bytes = subseq.encode('latin1')
    elif isinstance(subseq, bytes):
        subseq_bytes = subseq
    else:
        raise TypeError("subseq must be int, str, or bytes")

    full_pattern = cyclic(max_len, n=n)
    offset = full_pattern.find(subseq_bytes[:n])
    return offset


def parse_elf_header(data: bytes) -> Optional[Dict[str, Any]]:
    """Lightweight ELF header parser."""
    if not data.startswith(b'\x7fELF'):
        return None

    ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
    ei_data = data[5]   # 1 = Little-endian, 2 = Big-endian
    arch_str = "64-bit" if ei_class == 2 else "32-bit"
    endian_str = "little" if ei_data == 1 else "big"
    
    fmt_endian = '<' if ei_data == 1 else '>'
    
    if ei_class == 2:  # 64-bit ELF
        if len(data) >= 32:
            e_type, e_machine, e_version, e_entry = struct.unpack(f"{fmt_endian}HHIQ", data[16:32])
            return {
                "format": "ELF64",
                "arch": arch_str,
                "endian": endian_str,
                "entrypoint": hex(e_entry),
                "type": "Executable / Shared Object" if e_type in (2, 3) else hex(e_type)
            }
    else:  # 32-bit ELF
        if len(data) >= 28:
            e_type, e_machine, e_version, e_entry = struct.unpack(f"{fmt_endian}HHII", data[16:28])
            return {
                "format": "ELF32",
                "arch": arch_str,
                "endian": endian_str,
                "entrypoint": hex(e_entry),
                "type": "Executable / Shared Object" if e_type in (2, 3) else hex(e_type)
            }
    return {"format": "ELF", "arch": arch_str, "endian": endian_str}


def generate_gdb_init(breakpoints: List[str] = None, binary: str = "vuln") -> str:
    """Generates an optimal GDB debugging initialization script."""
    lines = [
        f"file {binary}",
        "set pagination off",
        "set disassembly-flavor intel",
        "set confirm off"
    ]
    if breakpoints:
        for bp in breakpoints:
            lines.append(f"break *{bp}")
    lines.append("run")
    return "\n".join(lines)
