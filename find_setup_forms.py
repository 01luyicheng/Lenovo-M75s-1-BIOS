#!/usr/bin/env python3
"""
Find the actual Setup DXE module that contains IFR forms.
The Setup module we found might just be a data module, not the actual form definition.
We need to find modules with HII form packages (type 0x02).
"""

import struct
import os

def find_form_packages(data, base_offset=0):
    """Find HII form packages in the data."""
    packages = []
    i = 0
    while i < len(data) - 4:
        pkg_type = data[i]
        pkg_len = struct.unpack('<I', data[i:i+3] + b'\x00')[0] & 0xFFFFFF
        if pkg_type == 0x02 and pkg_len >= 8 and pkg_len < 0x100000 and i + pkg_len <= len(data):
            first_op = data[i+4] & 0x7F if i+4 < len(data) else 0
            if first_op == 0x32:  # FORM_SET
                packages.append((base_offset + i, pkg_len))
                i += pkg_len
                continue
        i += 1
    return packages

def scan_dump_dir(dump_dir):
    """Scan all body.bin files for form packages."""
    results = []
    for root, dirs, files in os.walk(dump_dir):
        for f in files:
            if f == 'body.bin':
                path = os.path.join(root, f)
                try:
                    with open(path, 'rb') as fh:
                        data = fh.read()
                    pkgs = find_form_packages(data)
                    if pkgs:
                        # Get the parent directory name for context
                        parent = os.path.basename(root)
                        results.append({
                            'path': path,
                            'parent': parent,
                            'size': len(data),
                            'packages': pkgs
                        })
                except Exception as e:
                    pass
    return results

def main():
    dump_dir = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom.dump"

    print("Scanning all extracted body.bin files for HII form packages...")
    results = scan_dump_dir(dump_dir)

    print(f"\nFound {len(results)} files containing form packages:\n")
    for r in results:
        print(f"File: {r['path']}")
        print(f"  Parent: {r['parent']}")
        print(f"  Size: {r['size']} bytes")
        print(f"  Form packages: {len(r['packages'])}")
        for off, size in r['packages'][:5]:
            print(f"    Offset 0x{off:X}, size {size}")
        print()

    # Focus on the largest ones which are likely the main Setup modules
    results.sort(key=lambda x: x['size'], reverse=True)
    print("\nTop 10 largest form-containing files:")
    for r in results[:10]:
        print(f"  {r['size']:>10} bytes - {r['parent']}")

if __name__ == '__main__':
    main()
