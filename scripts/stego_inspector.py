#!/usr/bin/env python3
"""
omni-sec Multimodal Stego & Binary File Inspector CLI
Analyzes file signatures (magic bytes), detects hidden/trailing payloads (ZIP/tar/data appended after EOF),
extracts printable strings, and inspects PNG/BMP LSB bitplanes (inspired by zsteg).
Zero external dependencies (pure Python standard library: struct, zlib, re).
"""

import sys
import os
import argparse
import struct
import zlib
import re
from typing import Dict, List, Any, Optional

MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', "PNG Image", b'IEND\xaeB`\x82'),
    (b'\xff\xd8\xff', "JPEG Image", b'\xff\xd9'),
    (b'GIF87a', "GIF87a Image", b'\x00;'),
    (b'GIF89a', "GIF89a Image", b'\x00;'),
    (b'PK\x03\x04', "ZIP Archive (Local Header)", b'PK\x05\x06'),
    (b'%PDF-', "PDF Document", b'%%EOF'),
    (b'\x7fELF', "Linux ELF Executable/Object", None),
    (b'MZ', "Windows PE / DOS Executable", None),
    (b'SQLite format 3\x00', "SQLite 3 Database", None),
    (b'RIFF', "RIFF Container (WAV/AVI/WEBP)", None),
    (b'7z\xbc\xaf\x27\x1c', "7-Zip Archive", None),
    (b'Rar!\x1a\x07\x00', "RAR Archive v4", None),
    (b'Rar!\x1a\x07\x01\x00', "RAR Archive v5", None),
]

def analyze_magic_bytes(data: bytes) -> dict:
    matched = None
    for sig, label, trailer in MAGIC_SIGNATURES:
        if data.startswith(sig):
            matched = {"label": label, "signature": sig, "trailer": trailer}
            break
    if not matched:
        head_hex = data[:16].hex(" ") if len(data) >= 16 else data.hex(" ")
        return {"known": False, "label": "Unknown / Raw Binary", "head_hex": head_hex, "trailer": None}
    matched["known"] = True
    matched["head_hex"] = data[:len(matched["signature"])].hex(" ")
    return matched

def scan_embedded_zip(data: bytes) -> List[int]:
    results = []
    zip_sig = b'PK\x03\x04'
    offset = 0
    while True:
        idx = data.find(zip_sig, offset)
        if idx == -1:
            break
        results.append(idx)
        offset = idx + 4
    return results

def detect_trailing_data(data: bytes, trailer: Optional[bytes]) -> dict:
    if not trailer:
        return {"has_trailing": False, "trailer_offset": -1, "trailing_bytes": 0}
    idx = data.rfind(trailer)
    if idx == -1:
        return {"has_trailing": False, "trailer_offset": -1, "trailing_bytes": 0, "trailer_found": False}
    end_of_payload = idx + len(trailer)
    trailing_len = len(data) - end_of_payload
    return {
        "has_trailing": trailing_len > 0,
        "trailer_found": True,
        "trailer_offset": idx,
        "end_of_payload": end_of_payload,
        "trailing_bytes": trailing_len,
        "trailing_data_preview": data[end_of_payload:end_of_payload+64] if trailing_len > 0 else b""
    }

def extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    return [m.group(0).decode('ascii', errors='ignore') for m in re.finditer(pattern, data)]

def parse_png_lsb(data: bytes) -> Dict[str, Any]:
    """Pure-Python LSB extractor for PNG IDAT chunks (inspired by zsteg)."""
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        return {"is_png": False}

    offset = 8
    idat_data = bytearray()
    ihdr_parsed = False
    width, height, bit_depth, color_type = 0, 0, 0, 0

    while offset < len(data):
        if offset + 8 > len(data):
            break
        length, chunk_type = struct.unpack('>I4s', data[offset:offset+8])
        chunk_data = data[offset+8:offset+8+length]
        offset += 8 + length + 4  # +4 for CRC

        if chunk_type == b'IHDR' and len(chunk_data) >= 13:
            width, height, bit_depth, color_type = struct.unpack('>IIBB', chunk_data[:10])
            ihdr_parsed = True
        elif chunk_type == b'IDAT':
            idat_data.extend(chunk_data)
        elif chunk_type == b'IEND':
            break

    if not ihdr_parsed or not idat_data:
        return {"is_png": True, "lsb_extracted": False}

    try:
        decompressed = zlib.decompress(bytes(idat_data))
    except Exception:
        return {"is_png": True, "lsb_extracted": False}

    # Extract raw LSB bits from decompressed bytes
    bits = [b & 1 for b in decompressed]
    extracted_bytes = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte_val = 0
        for bit_idx in range(8):
            byte_val = (byte_val << 1) | bits[i + bit_idx]
        extracted_bytes.append(byte_val)

    lsb_strings = extract_strings(bytes(extracted_bytes), min_len=5)
    flag_matches = [s for s in lsb_strings if re.search(r'(flag|ctf|pico|sec)\{.*?\}', s, re.IGNORECASE)]

    return {
        "is_png": True,
        "width": width,
        "height": height,
        "bit_depth": bit_depth,
        "color_type": color_type,
        "lsb_extracted": True,
        "lsb_flags": flag_matches,
        "lsb_sample_strings": lsb_strings[:10],
        "raw_preview": extracted_bytes[:32].hex(" ")
    }

def inspect_file(filepath: str, extract_trailing_to: Optional[str] = None) -> dict:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    file_size = os.path.getsize(filepath)
    with open(filepath, 'rb') as f:
        data = f.read()

    magic_info = analyze_magic_bytes(data)
    zip_offsets = scan_embedded_zip(data)
    trailing_info = detect_trailing_data(data, magic_info.get("trailer"))
    strings_found = extract_strings(data, min_len=6)
    flag_candidates = [s for s in strings_found if re.search(r'(flag|ctf|pico|sec)\{.*?\}', s, re.IGNORECASE)]
    png_lsb = parse_png_lsb(data) if magic_info.get("label") == "PNG Image" else None

    if extract_trailing_to and trailing_info.get("has_trailing"):
        trailing_data = data[trailing_info["end_of_payload"]:]
        with open(extract_trailing_to, 'wb') as out_f:
            out_f.write(trailing_data)

    return {
        "filepath": filepath,
        "size": file_size,
        "magic": magic_info,
        "embedded_zips": zip_offsets,
        "trailing": trailing_info,
        "png_lsb": png_lsb,
        "total_strings": len(strings_found),
        "flag_candidates": flag_candidates,
        "strings_sample": strings_found[:15]
    }

def main():
    parser = argparse.ArgumentParser(description="omni-sec Multimodal Stego & Binary File Inspector")
    parser.add_argument("--file", type=str, required=True, help="Target file path to inspect")
    parser.add_argument("--extract-trailing", type=str, help="Output path to dump trailing bytes if detected")
    parser.add_argument("--strings", action="store_true", help="Dump printable strings from binary")

    args = parser.parse_args()
    try:
        report = inspect_file(args.file, args.extract_trailing)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)

    print("\n" + "="*60)
    print(" [omni-sec File Forensics & Stego Analysis]")
    print("="*60)
    print(f" File Target : {report['filepath']}")
    print(f" File Size   : {report['size']:,} bytes")
    print(f" Magic Match : {report['magic']['label']}")

    if report.get("png_lsb") and report["png_lsb"].get("lsb_extracted"):
        lsb = report["png_lsb"]
        print(f"\n [+] PNG Metadata: {lsb['width']}x{lsb['height']} (Depth: {lsb['bit_depth']}, Color: {lsb['color_type']})")
        if lsb.get("lsb_flags"):
            print(" [🔥] LSB STEGO FLAGS DETECTED (zsteg analysis):")
            for fl in lsb["lsb_flags"]:
                print(f"      -> {fl}")
        elif lsb.get("lsb_sample_strings"):
            print(f" [+] LSB Extracted Strings: {lsb['lsb_sample_strings'][:5]}")

    if report['embedded_zips']:
        print(f"\n [+] Embedded ZIP Signatures Detected at offset(s): {report['embedded_zips']}")
        if report['embedded_zips'][0] > 0:
            print("     -> Potential Polyglot / Hidden Archive (Non-zero offset)!")

    trailing = report['trailing']
    if trailing.get("has_trailing"):
        print(f"\n [!] TRAILING BYTES DETECTED AFTER EOF:")
        print(f"     Trailer offset : 0x{trailing['trailer_offset']:X}")
        print(f"     Trailing size  : {trailing['trailing_bytes']:,} bytes")
        if args.extract_trailing:
            print(f"     [+] Dumped trailing data to: {args.extract_trailing}")

    if report['flag_candidates']:
        print(f"\n [+] POTENTIAL FLAG MATCHES IN STRINGS:")
        for fc in report['flag_candidates']:
            print(f"     -> {fc}")

    print("="*60 + "\n")

if __name__ == '__main__':
    main()
