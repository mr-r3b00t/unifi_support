#!/usr/bin/env python3
"""
Decrypt and extract UniFi backup files (.unifi / .unf).

Two formats are supported:

1. Legacy .unf (Network Application backups):
   - AES-128-CBC with hardcoded key/IV
   - Key: bcyangkmluohmars  IV: ubntenterpriseap
   - Contains ZIP -> db.gz (MongoDB BSON)

2. UniFi OS v2 .unifi (Console/System backups):
   - First 16 bytes = IV, AES-256-CBC with hardcoded key
   - Decrypted data is gzip-compressed tar archive
   - Contains network config, ucore PostgreSQL DB, certificates, etc.

Usage:
    python3 decrypt_unifi_backup.py [backup_file]
"""

import sys
import os
import io
import json
import zipfile
import zlib
import tarfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    print("Error: 'cryptography' package is required.")
    print("Install it with: pip3 install cryptography")
    sys.exit(1)


# Legacy .unf encryption parameters (AES-128-CBC)
UNF_KEY = b"bcyangkmluohmars"
UNF_IV  = b"ubntenterpriseap"

# UniFi OS v2 .unifi encryption parameters (AES-256-CBC)
UNIFI_V2_KEY = bytes.fromhex(
    "e383b7c53698b36d4baea4ed22181ef73676bfd5d5b90005d9845ffd5dce985f"
)


def decrypt_unf(data):
    """Decrypt legacy .unf backup (AES-128-CBC, static key/IV)."""
    aligned_len = (len(data) // 16) * 16
    if aligned_len == 0:
        raise ValueError("File too small to decrypt")
    cipher = Cipher(algorithms.AES(UNF_KEY), modes.CBC(UNF_IV))
    dec = cipher.decryptor()
    return dec.update(data[:aligned_len]) + dec.finalize()


def decrypt_unifi_v2(data):
    """Decrypt UniFi OS v2 backup.

    Format: [16-byte IV] [AES-256-CBC ciphertext] -> gzip -> tar
    """
    iv = data[:16]
    ciphertext = data[16:]
    aligned_len = (len(ciphertext) // 16) * 16
    if aligned_len == 0:
        raise ValueError("File too small to decrypt")

    cipher = Cipher(algorithms.AES(UNIFI_V2_KEY), modes.CBC(iv))
    dec = cipher.decryptor()
    decrypted = dec.update(ciphertext[:aligned_len]) + dec.finalize()

    # Decompress gzip (use zlib to handle CBC padding junk at end)
    try:
        decompressor = zlib.decompressobj(31)  # wbits=31 for gzip
        decompressed = decompressor.decompress(decrypted)
        decompressed += decompressor.flush()
        print(f"Decompressed: {len(decrypted):,} -> {len(decompressed):,} bytes")
        return decompressed
    except Exception as e:
        print(f"Gzip decompression failed ({e}), returning raw")
        return decrypted


def extract_tar(data, output_dir):
    """Extract a tar archive and return the file list."""
    os.makedirs(output_dir, exist_ok=True)
    buf = io.BytesIO(data)
    with tarfile.open(fileobj=buf, mode="r:") as tf:
        members = tf.getmembers()
        tf.extractall(output_dir)
    return members


def extract_zip(data, output_dir):
    """Extract a ZIP archive and return the file list."""
    os.makedirs(output_dir, exist_ok=True)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
    except zipfile.BadZipFile:
        # Try trimming CBC padding
        for trim in range(1, 17):
            try:
                zf = zipfile.ZipFile(io.BytesIO(data[:-trim]), "r")
                break
            except zipfile.BadZipFile:
                continue
        else:
            return None
    names = zf.namelist()
    zf.extractall(output_dir)
    zf.close()
    return names


def main():
    if len(sys.argv) < 2:
        unifi_files = list(Path(".").glob("*.unifi")) + list(Path(".").glob("*.unf"))
        if len(unifi_files) == 1:
            filepath = str(unifi_files[0])
            print(f"Found backup: {filepath}")
        elif len(unifi_files) > 1:
            print("Multiple backup files found. Please specify one:")
            for f in unifi_files:
                print(f"  {f}")
            sys.exit(1)
        else:
            print(f"Usage: {sys.argv[0]} <backup_file>")
            sys.exit(1)
    else:
        filepath = sys.argv[1]

    if not os.path.isfile(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    print(f"Reading: {filepath}")
    with open(filepath, "rb") as f:
        data = f.read()
    print(f"File size: {len(data):,} bytes")

    is_v2 = filepath.endswith(".unifi")

    if is_v2:
        print("Detected UniFi OS v2 format (.unifi)")
        print(f"IV (first 16 bytes): {data[:16].hex()}")
        print("Decrypting (AES-256-CBC)...")
        decrypted = decrypt_unifi_v2(data)
    else:
        print("Detected legacy format (.unf)")
        print("Decrypting (AES-128-CBC)...")
        decrypted = decrypt_unf(data)

    backup_name = Path(filepath).stem
    output_dir = os.path.join(os.path.dirname(filepath) or ".", f"{backup_name}_extracted")

    # Detect container format and extract
    if decrypted[:6] in (b"backup", b"backu/") or b"backup/" in decrypted[:512]:
        # tar archive (UniFi OS v2)
        print("Extracting tar archive...")
        members = extract_tar(decrypted, output_dir)
        files = [m for m in members if m.isfile()]
        dirs = [m for m in members if m.isdir()]
        print(f"\nExtracted {len(files)} files in {len(dirs)} directories.")
        print("-" * 60)
        for m in sorted(files, key=lambda x: x.name):
            print(f"  {m.size:>12,} B  {m.name}")
    elif decrypted[:2] == b"PK":
        # ZIP archive (legacy .unf)
        print("Extracting ZIP archive...")
        names = extract_zip(decrypted, output_dir)
        if names:
            print(f"\nExtracted {len(names)} files.")
            for n in sorted(names):
                print(f"  {n}")
        else:
            raw_path = os.path.join(output_dir, "backup_raw.zip")
            with open(raw_path, "wb") as f:
                f.write(decrypted)
            print(f"ZIP extraction failed. Raw file saved to: {raw_path}")
            print(f"Try: zip -FF {raw_path} --out fixed.zip")
    else:
        raw_path = os.path.join(output_dir, "decrypted.bin")
        os.makedirs(output_dir, exist_ok=True)
        with open(raw_path, "wb") as f:
            f.write(decrypted)
        print(f"Unknown format. First 16 bytes: {decrypted[:16].hex()}")
        print(f"Raw output: {raw_path}")

    print(f"\nDone. Extracted to: {os.path.abspath(output_dir)}")


if __name__ == "__main__":
    main()
