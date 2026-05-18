#!/usr/bin/env python3
"""
AMI Aptio BIOS Firmware Analyzer
Analyzes IMAGEM2C.rom for Setup modules, IFR data, and AMD-related modules.
"""

import sys
import os
import struct
import json
from uefi_firmware import AutoParser

ROM_PATH = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"
OUTPUT_DIR = "/workspace/bios_extract"

def guid_to_str(guid_bytes):
    """Convert 16-byte GUID to standard string format."""
    if len(guid_bytes) != 16:
        return "INVALID"
    # GUID structure: uint32, uint16, uint16, uint8[8]
    a, b, c = struct.unpack('<IHH', guid_bytes[:8])
    d = guid_bytes[8:]
    return f"{a:08X}-{b:04X}-{c:04X}-{d[0]:02X}{d[1]:02X}-{d[2]:02X}{d[3]:02X}{d[4]:02X}{d[5]:02X}{d[6]:02X}{d[7]:02X}"

def analyze_bios():
    if not os.path.exists(ROM_PATH):
        print(f"ERROR: ROM file not found: {ROM_PATH}")
        sys.exit(1)

    file_size = os.path.getsize(ROM_PATH)
    print(f"BIOS ROM: {ROM_PATH}")
    print(f"Size: {file_size} bytes ({file_size / (1024*1024):.2f} MB)")
    print("=" * 80)

    with open(ROM_PATH, 'rb') as f:
        parser = AutoParser(f.read())

    if not parser.type():
        print("ERROR: Could not identify firmware type.")
        sys.exit(1)

    print(f"Detected firmware type: {parser.type()}")
    firmware = parser.parse()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_modules = []
    setup_modules = []
    amd_modules = []
    ifr_modules = []

    def walk_objects(obj, path=""):
        """Recursively walk firmware objects and collect info."""
        obj_type = type(obj).__name__
        name = getattr(obj, 'name', '') or ''
        if isinstance(name, int):
            name = str(name)
        guid = getattr(obj, 'guid', None)
        guid_str = guid_to_str(guid) if guid else ''
        offset = getattr(obj, 'offset', 0) or 0
        size = 0

        # Try to get size from data or object
        data = getattr(obj, 'data', None)
        if data is not None:
            size = len(data)

        # Try to get size from attrs
        if not size:
            size = getattr(obj, 'size', 0) or 0

        # Build path string
        current_path = f"{path}/{name}" if path else name

        obj_info = {
            'type': obj_type,
            'name': name,
            'guid': guid_str,
            'offset': offset,
            'size': size,
            'path': current_path,
        }

        # Filter for real modules with data
        if size > 0 and (guid_str or name):
            all_modules.append(obj_info)

            # Check for Setup-related modules
            setup_keywords = ['setup', 'amitse', 'tse', 'setuputility', 'setupdata', 'ifrbrowser', 'formbrowser']
            if any(kw in name.lower() for kw in setup_keywords):
                setup_modules.append(obj_info)

            # Check for AMD modules
            amd_keywords = ['amd', 'cbs', 'pbs', 'agesa', 'promontory']
            if any(kw in name.lower() for kw in amd_keywords):
                amd_modules.append(obj_info)

            # Check for IFR data in PE32/DXE sections
            if data and b'IFR' in data[:min(1024, len(data))]:
                ifr_modules.append(obj_info)

            # Also scan raw data for IFR signature
            if data and len(data) > 4:
                # IFR forms often start with EFI_IFR_FORM_SET_OP (0x0E) or similar
                # Look for common IFR patterns
                if b'\x0e\x00' in data[:256] or b'\x01\x00\x0e\x00' in data[:256]:
                    if obj_info not in ifr_modules:
                        ifr_modules.append(obj_info)

        # Recurse into children
        children = getattr(obj, 'objects', None)
        if children:
            for child in children:
                walk_objects(child, current_path)

    walk_objects(firmware)

    # Also do raw scan for IFR signatures across the whole ROM
    print("\nScanning raw ROM for IFR signatures...")
    with open(ROM_PATH, 'rb') as f:
        raw = f.read()

    # EFI_IFR_FORM_SET_OP = 0x0E
    raw_ifr_offsets = []
    for i in range(len(raw) - 4):
        # Look for IFR form set opcode patterns
        if raw[i:i+2] == b'\x0e\x00' and raw[i+2] > 0:
            # Check for reasonable IFR length
            if raw[i+3] < 0x20:
                raw_ifr_offsets.append(i)

    print(f"Found {len(raw_ifr_offsets)} potential raw IFR offsets")

    # Save reports
    with open(os.path.join(OUTPUT_DIR, 'all_modules.json'), 'w') as f:
        json.dump(all_modules, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, 'setup_modules.json'), 'w') as f:
        json.dump(setup_modules, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, 'amd_modules.json'), 'w') as f:
        json.dump(amd_modules, f, indent=2)

    with open(os.path.join(OUTPUT_DIR, 'ifr_modules.json'), 'w') as f:
        json.dump(ifr_modules, f, indent=2)

    # Print summary
    print("\n" + "=" * 80)
    print(f"TOTAL MODULES FOUND: {len(all_modules)}")
    print(f"SETUP-RELATED MODULES: {len(setup_modules)}")
    print(f"AMD-RELATED MODULES: {len(amd_modules)}")
    print(f"IFR MODULES: {len(ifr_modules)}")
    print("=" * 80)

    print("\n--- SETUP MODULES ---")
    for m in setup_modules:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    print("\n--- AMD MODULES ---")
    for m in amd_modules:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    print("\n--- IFR MODULES ---")
    for m in ifr_modules:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    # Extract PE32/DXE modules for Setup-related items
    print("\n--- EXTRACTING SETUP MODULES ---")
    extracted_count = 0
    for m in setup_modules + amd_modules:
        if m['size'] > 0:
            safe_name = m['name'].replace('/', '_').replace('\\', '_').replace(' ', '_') or 'unknown'
            filename = f"{m['offset']:08X}_{safe_name}_{m['guid'] or 'NOGUID'}.bin"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(ROM_PATH, 'rb') as f:
                f.seek(m['offset'])
                data = f.read(m['size'])
            with open(filepath, 'wb') as ef:
                ef.write(data)
            extracted_count += 1
            print(f"  Extracted: {filename} ({m['size']:,} bytes)")

    print(f"\nExtracted {extracted_count} modules to {OUTPUT_DIR}")

if __name__ == '__main__':
    analyze_bios()
