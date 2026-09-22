import pytest
import os
import tempfile
from scripts.stego_inspector import inspect_file, analyze_magic_bytes, scan_embedded_zip, detect_trailing_data

def test_magic_bytes_png():
    png_header = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR'
    info = analyze_magic_bytes(png_header)
    assert info["known"] is True
    assert "PNG" in info["label"]

def test_magic_bytes_jpeg():
    jpg_header = b'\xff\xd8\xff\xe0\x00\x10JFIF'
    info = analyze_magic_bytes(jpg_header)
    assert info["known"] is True
    assert "JPEG" in info["label"]

def test_embedded_zip_detection():
    data = b'DUMMY_IMAGE_DATA...' + b'PK\x03\x04' + b'ZIP_FILE_CONTENT'
    offsets = scan_embedded_zip(data)
    assert len(offsets) == 1
    assert offsets[0] > 0

def test_trailing_data_detection():
    # PNG with IEND trailer + appended flag secret
    png_with_trailing = b'\x89PNG\r\n\x1a\n' + b'IEND\xaeB`\x82' + b'flag{hidden_in_trailing_bytes}'
    trailer = b'IEND\xaeB`\x82'
    trailing = detect_trailing_data(png_with_trailing, trailer)
    assert trailing["has_trailing"] is True
    assert trailing["trailing_bytes"] == len(b'flag{hidden_in_trailing_bytes}')

def test_full_inspect_file():
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b'\x89PNG\r\n\x1a\n' + b'IEND\xaeB`\x82' + b'flag{sample_flag}')
        tmp_path = tf.name

    try:
        report = inspect_file(tmp_path)
        assert report["magic"]["known"] is True
        assert report["trailing"]["has_trailing"] is True
        assert "flag{sample_flag}" in report["flag_candidates"]
    finally:
        os.remove(tmp_path)
