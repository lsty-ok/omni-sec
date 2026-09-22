#!/usr/bin/env python3
"""
omni-sec Multimodal Stego & Binary File Inspector CLI
Analyzes file signatures (magic bytes), detects hidden/trailing payloads (ZIP/tar/data appended after EOF),
extracts printable strings, and inspects PNG/JPEG chunks.
Zero external dependencies (pure Python standard library).
"""

import sys
import os
import argparse
import struct
import re

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

def scan_embedded_zip(data: bytes) -> list:
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

def detect_trailing_data(data: bytes, trailer: bytes) -> dict:
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

def extract_strings(data: bytes, min_len: int = 6) -> list:
    pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
    return [m.group(0).decode('ascii', errors='ignore') for m in re.finditer(pattern, data)]

def inspect_file(filepath: str, extract_trailing_to: str = None) -> dict:
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
    print(f" [omni-sec File Forensics & Stego Analysis]")
    print("="*60)
    print(f" File Target : {report['filepath']}")
    print(f" File Size   : {report['size']:,} bytes")
    print(f" Magic Match : {report['magic']['label']}")
    print(f" Header Hex  : {report['magic']['head_hex']}")

    if report['embedded_zips']:
        print(f"\n [+] Embedded ZIP Signatures Detected at offset(s): {report['embedded_zips']}")
        if report['embedded_zips'][0] > 0:
            print(f"     -> Potential Polyglot / Hidden Archive (Non-zero offset)!")

    trailing = report['trailing']
    if trailing.get("has_trailing"):
        print(f"\n [!] TRAILING BYTES DETECTED AFTER EOF:")
        print(f"     Trailer offset : 0x{trailing['trailer_offset']:X}")
        print(f"     Trailing size  : {trailing['trailing_bytes']:,} bytes")
        print(f"     Preview (Hex)  : {trailing['trailing_data_preview'][:32].hex(' ')}")
        if args.extract_trailing:
            print(f"     [+] Dumped trailing data to: {args.extract_trailing}")
    elif trailing.get("trailer_found") is False:
        print(f"\n [?] Warning: Standard EOF marker for {report['magic']['label']} was NOT found (File may be truncated).")

    if report['flag_candidates']:
        print(f"\n [+] POTENTIAL FLAG MATCHES IN STRINGS:")
        for fc in report['flag_candidates']:
            print(f"     -> {fc}")

    if args.strings:
        print(f"\n [Extracting Printable Strings (Sample of {report['total_strings']})]:")
        for s in report['strings_sample']:
            print(f"     {s}")

    print("="*60 + "\n")

if __name__ == '__main__':
    main()
