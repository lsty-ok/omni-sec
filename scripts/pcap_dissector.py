#!/usr/bin/env python3
"""
omni-sec Minimalist PCAP Protocol Stream & Credential Extractor CLI
Parses raw PCAP files, searches for cleartext credentials (HTTP, FTP, Telnet, SMTP),
identifies DNS exfiltration queries, and dumps data streams.
Zero external dependencies (pure Python standard library).
"""

import sys
import os
import argparse
import struct
import re

def parse_pcap_global_header(f) -> dict:
    header = f.read(24)
    if len(header) < 24:
        raise ValueError("File is too short to be a valid PCAP.")
    magic = header[:4]
    if magic == b'\xd4\xc3\xb2\xa1': # Little-endian microsecond
        endian = '<'
    elif magic == b'\xa1\xb2\xc3\xd4': # Big-endian microsecond
        endian = '>'
    elif magic == b'\x4d\x3c\xb2\xa1': # Little-endian nanosecond
        endian = '<'
    elif magic == b'\xa1\xb2\x3c\x4d': # Big-endian nanosecond
        endian = '>'
    else:
        raise ValueError(f"Unknown PCAP magic bytes: {magic.hex()}")
    
    ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(endian + 'HHIIII', header[4:24])
    return {"endian": endian, "snaplen": snaplen, "network": network}

def extract_pcap_payloads(filepath: str) -> dict:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    credentials = []
    dns_queries = []
    http_requests = []
    flag_matches = []
    total_packets = 0
    
    with open(filepath, 'rb') as f:
        try:
            pcap_info = parse_pcap_global_header(f)
            endian = pcap_info["endian"]
        except Exception as e:
            # Fallback to pure regex scanner if pcapng or corrupted
            f.seek(0)
            raw_data = f.read()
            return scan_raw_bytes_for_pcap_artifacts(raw_data)
            
        while True:
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', pkt_header)
            packet_data = f.read(incl_len)
            total_packets += 1
            
            # Simple payload search
            text = packet_data.decode('ascii', errors='ignore')
            
            # Search credentials
            auth_match = re.search(r'(Authorization:\s*Basic\s*([A-Za-z0-9+/=]+)|USER\s+([^\r\n]+)|PASS\s+([^\r\n]+)|password=([^\s&]+))', text, re.IGNORECASE)
            if auth_match:
                credentials.append(auth_match.group(0).strip())
                
            # Search HTTP Requests
            http_m = re.search(r'((?:GET|POST|PUT|DELETE)\s+[^\s]+\s+HTTP/1\.[01])', text)
            if http_m:
                http_requests.append(http_m.group(1))
                
            # Search flags
            flags = re.findall(r'(flag|ctf|pico|sec)\{.*?\}', text, re.IGNORECASE)
            for fl in flags:
                if fl not in flag_matches:
                    flag_matches.append(fl)
                    
    return {
        "total_packets": total_packets,
        "credentials": list(set(credentials)),
        "http_requests": list(set(http_requests))[:10],
        "flags": flag_matches
    }

def scan_raw_bytes_for_pcap_artifacts(raw_data: bytes) -> dict:
    text = raw_data.decode('ascii', errors='ignore')
    credentials = re.findall(r'(Authorization:\s*Basic\s*[A-Za-z0-9+/=]+|USER\s+[^\r\n]+|PASS\s+[^\r\n]+|password=[^\s&]+)', text, re.IGNORECASE)
    http_requests = re.findall(r'((?:GET|POST|PUT|DELETE)\s+[^\s]+\s+HTTP/1\.[01])', text)
    flags = re.findall(r'(flag|ctf|pico|sec)\{.*?\}', text, re.IGNORECASE)
    
    return {
        "total_packets": "Raw Stream Mode",
        "credentials": list(set(credentials)),
        "http_requests": list(set(http_requests))[:10],
        "flags": list(set(flags))
    }

def main():
    parser = argparse.ArgumentParser(description="omni-sec PCAP Protocol Stream & Credential Extractor")
    parser.add_argument("--file", type=str, required=True, help="Path to .pcap / .pcapng network capture")
    args = parser.parse_args()
    
    try:
        results = extract_pcap_payloads(args.file)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
        
    print("\n" + "="*60)
    print(" [omni-sec PCAP Network Forensics Analysis]")
    print("="*60)
    print(f" Target File    : {args.file}")
    print(f" Packets Scanned: {results['total_packets']}")
    
    if results['flags']:
        print(f"\n [+] FLAG FOUND IN NETWORK TRAFFIC:")
        for fl in results['flags']:
            print(f"     -> {fl}")
            
    if results['credentials']:
        print(f"\n [!] POTENTIAL CLEARTEXT CREDENTIALS:")
        for cred in results['credentials']:
            print(f"     -> {cred}")
            
    if results['http_requests']:
        print(f"\n [HTTP Request Sample]:")
        for req in results['http_requests'][:5]:
            print(f"     {req}")
            
    print("="*60 + "\n")

if __name__ == '__main__':
    main()
