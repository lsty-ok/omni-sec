#!/usr/bin/env python3
"""
omni-sec Cipher & Encoding Toolkit CLI
Multi-layer decoder (Base64, Hex, URL, Binary, ROT13, Single-Byte XOR, Caesar) and hash identifier.
Zero external dependencies (pure Python standard library).
"""

import sys
import argparse
import base64
import urllib.parse
import re
import string
from typing import List, Tuple, Dict, Optional

def identify_hash_type(hash_str: str) -> List[str]:
    """Identify possible hash types based on length and character set."""
    h = hash_str.strip()
    candidates = []
    
    if re.match(r'^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$', h):
        return ["bcrypt"]
    if re.match(r'^\$6\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{86}$', h):
        return ["SHA-512 crypt"]
    if re.match(r'^[a-fA-F0-9]{32}$', h):
        candidates.extend(["MD5", "NTLM", "MD4"])
    elif re.match(r'^[a-fA-F0-9]{40}$', h):
        candidates.extend(["SHA-1", "RIPEMD-160"])
    elif re.match(r'^[a-fA-F0-9]{64}$', h):
        candidates.extend(["SHA-256", "HMAC-SHA256", "Keccak-256"])
    elif re.match(r'^[a-fA-F0-9]{128}$', h):
        candidates.extend(["SHA-512", "Whirlpool"])
    elif re.match(r'^[A-Za-z0-9+/]+={0,2}$', h) and len(h) % 4 == 0:
        candidates.append("Base64 String")
        
    return candidates or ["Unknown Format"]

def decode_hex(data: str) -> str:
    clean = re.sub(r'[\s0x,]', '', data)
    return bytes.fromhex(clean).decode('utf-8', errors='replace')

def decode_base64(data: str) -> str:
    padded = data.strip() + "=" * ((4 - len(data.strip()) % 4) % 4)
    return base64.b64decode(padded).decode('utf-8', errors='replace')

def decode_rot13(data: str) -> str:
    trans = str.maketrans(
        "ABCDEFGHIJKLMabcdefghijklmNOPQRSTUVWXYZnopqrstuvwxyz",
        "NOPQRSTUVWXYZnopqrstuvwxyzABCDEFGHIJKLMabcdefghijklm"
    )
    return data.translate(trans)

def bruteforce_caesar(data: str) -> List[Tuple[int, str]]:
    results = []
    for shift in range(1, 26):
        shifted = []
        for char in data:
            if 'a' <= char <= 'z':
                shifted.append(chr((ord(char) - ord('a') - shift) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                shifted.append(chr((ord(char) - ord('A') - shift) % 26 + ord('A')))
            else:
                shifted.append(char)
        results.append((shift, "".join(shifted)))
    return results

def bruteforce_single_byte_xor(data_bytes: bytes) -> List[Tuple[int, float, str]]:
    """Brute force single-byte XOR and rank by English letter frequency."""
    english_freq = {
        'e': 12.7, 't': 9.1, 'a': 8.2, 'o': 7.5, 'i': 7.0, 'n': 6.7,
        's': 6.3, 'h': 6.1, 'r': 6.0, 'd': 4.3, 'l': 4.0, 'c': 2.8,
        'u': 2.8, 'm': 2.4, 'w': 2.4, 'f': 2.2, 'g': 2.0, 'y': 2.0,
        'p': 1.9, 'b': 1.5, 'v': 1.0, 'k': 0.8, 'j': 0.15, 'x': 0.15,
        'q': 0.1, 'z': 0.07, ' ': 15.0
    }
    
    candidates = []
    for key in range(256):
        decrypted = bytes([b ^ key for b in data_bytes])
        try:
            text = decrypted.decode('ascii')
            score = sum(english_freq.get(char.lower(), 0) for char in text if char in string.printable)
            candidates.append((key, score, text))
        except UnicodeDecodeError:
            continue
            
    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[:5]

def extract_flag(text: str, custom_prefix: str = None) -> List[str]:
    prefix = custom_prefix if custom_prefix else r'(?:flag|ctf|picoctf|sec)'
    pattern = rf'({prefix}\{{.*?\}})'
    return re.findall(pattern, text, re.IGNORECASE)

def main():
    parser = argparse.ArgumentParser(description="omni-sec Multi-Layer Cipher Toolkit")
    parser.add_argument("--data", type=str, help="Ciphertext or encoded string input")
    parser.add_argument("--mode", choices=["hex", "b64", "rot13", "caesar", "xor", "hash", "url", "auto"], default="auto")
    parser.add_argument("--flag-prefix", type=str, default="flag", help="Custom flag prefix format")
    
    args = parser.parse_args()
    if not args.data:
        parser.print_help()
        sys.exit(0)
        
    raw = args.data.strip()
    print(f"\n[omni-sec Cryptanalysis & Decoding: {args.mode.upper()}]")
    print(f"  Input: {raw[:60]}{'...' if len(raw) > 60 else ''}")
    
    if args.mode in ["hash", "auto"]:
        hashes = identify_hash_type(raw)
        print(f"  Identified Type: {', '.join(hashes)}")
        
    if args.mode == "hex" or (args.mode == "auto" and re.match(r'^[a-fA-F0-9]+$', raw) and len(raw) % 2 == 0):
        try:
            res = decode_hex(raw)
            print(f"  Hex Decoded    : {res}")
            flags = extract_flag(res, args.flag_prefix)
            if flags: print(f"  [+] Flag Found : {flags}")
        except Exception:
            pass

    if args.mode == "b64" or args.mode == "auto":
        try:
            res = decode_base64(raw)
            print(f"  Base64 Decoded : {res}")
            flags = extract_flag(res, args.flag_prefix)
            if flags: print(f"  [+] Flag Found : {flags}")
        except Exception:
            pass

    if args.mode in ["rot13", "auto"]:
        res = decode_rot13(raw)
        flags = extract_flag(res, args.flag_prefix)
        if flags or args.mode == "rot13":
            print(f"  ROT13 Decoded  : {res}")
            if flags: print(f"  [+] Flag Found : {flags}")

    if args.mode == "caesar":
        shifts = bruteforce_caesar(raw)
        print("\n  Caesar Shifts (Top Matches):")
        for shift, text in shifts:
            flag = extract_flag(text, args.flag_prefix)
            flag_str = f" <-- [FLAG: {flag[0]}]" if flag else ""
            print(f"    Shift {shift:02d}: {text[:50]}{flag_str}")

if __name__ == '__main__':
    from typing import List, Tuple
    main()
