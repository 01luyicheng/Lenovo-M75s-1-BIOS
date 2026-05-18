#!/usr/bin/env python3
"""
AMI Aptio BIOS Firmware Analyzer v2
Enhanced parser for IMAGEM2C.rom with proper offset tracking and IFR extraction.
"""

import sys
import os
import struct
import json
from uefi_firmware import AutoParser
from uefi_firmware.uefi import FirmwareFileSystemSection, FirmwareFile, GuidDefinedSection

ROM_PATH = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"
OUTPUT_DIR = "/workspace/bios_extract_v2"

def guid_to_str(guid_bytes):
    if len(guid_bytes) != 16:
        return ""
    a, b, c = struct.unpack('<IHH', guid_bytes[:8])
    d = guid_bytes[8:]
    return f"{a:08X}-{b:04X}-{c:04X}-{d[0]:02X}{d[1]:02X}-{d[2]:02X}{d[3]:02X}{d[4]:02X}{d[5]:02X}{d[6]:02X}{d[7]:02X}"

def get_object_info(obj, parent_offset=0):
    """Extract comprehensive info from firmware object."""
    obj_type = type(obj).__name__
    name = getattr(obj, 'name', '') or ''
    if isinstance(name, int):
        name = str(name)

    guid = getattr(obj, 'guid', None)
    guid_str = guid_to_str(guid) if guid else ''

    # Calculate absolute offset
    obj_offset = getattr(obj, 'offset', 0) or 0
    abs_offset = parent_offset + obj_offset

    data = getattr(obj, 'data', None)
    size = len(data) if data is not None else (getattr(obj, 'size', 0) or 0)

    return {
        'type': obj_type,
        'name': name,
        'guid': guid_str,
        'offset': abs_offset,
        'size': size,
        'data_present': data is not None and len(data) > 0,
    }

def analyze_bios():
    if not os.path.exists(ROM_PATH):
        print(f"ERROR: ROM file not found: {ROM_PATH}")
        sys.exit(1)

    file_size = os.path.getsize(ROM_PATH)
    print(f"BIOS ROM: {ROM_PATH}")
    print(f"Size: {file_size} bytes ({file_size / (1024*1024):.2f} MB)")
    print("=" * 80)

    with open(ROM_PATH, 'rb') as f:
        rom_data = f.read()

    parser = AutoParser(rom_data)

    if not parser.type():
        print("ERROR: Could not identify firmware type.")
        sys.exit(1)

    print(f"Detected firmware type: {parser.type()}")
    firmware = parser.parse()

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_modules = []
    setup_modules = []
    amd_modules = []
    ifr_candidates = []
    large_modules = []

    def walk_objects(obj, parent_offset=0, path=""):
        info = get_object_info(obj, parent_offset)
        current_path = f"{path}/{info['name']}" if path else info['name']
        info['path'] = current_path

        # Track all modules with real data
        if info['size'] > 0:
            all_modules.append(info)

            # Categorize by size
            if info['size'] > 10000:
                large_modules.append(info)

            # Setup-related
            setup_keywords = ['setup', 'amitse', 'tse', 'setuputility', 'setupdata', 'ifrbrowser', 'formbrowser']
            if any(kw in info['name'].lower() for kw in setup_keywords):
                setup_modules.append(info)

            # AMD-related
            amd_keywords = ['amd', 'cbs', 'pbs', 'agesa', 'promontory']
            if any(kw in info['name'].lower() for kw in amd_keywords):
                amd_modules.append(info)

            # IFR candidate scan on data
            if info['data_present']:
                data = obj.data
                # Scan for IFR opcodes in first 1KB
                scan_len = min(1024, len(data))
                for i in range(scan_len - 4):
                    # EFI_IFR_FORM_SET_OP = 0x0E
                    if data[i] == 0x0E and data[i+1] == 0x00:
                        # Additional validation: check for reasonable scope opcodes nearby
                        if i + 3 < scan_len and data[i+3] < 0x40:
                            ifr_candidates.append({
                                **info,
                                'ifr_offset_in_module': i,
                                'ifr_signature': data[i:i+8].hex()
                            })
                            break

        # Recurse
        children = getattr(obj, 'objects', None)
        if children:
            for child in children:
                walk_objects(child, info['offset'], current_path)

    walk_objects(firmware)

    # Also do raw ROM scan for IFR patterns
    print("\nScanning raw ROM for IFR signatures...")
    raw_ifr_locations = []
    for i in range(len(rom_data) - 8):
        if rom_data[i] == 0x0E and rom_data[i+1] == 0x00:
            if rom_data[i+3] < 0x40 and rom_data[i+2] > 0:
                # Check for form set GUID pattern nearby
                raw_ifr_locations.append(i)

    print(f"Found {len(raw_ifr_locations)} potential raw IFR offsets")

    # Deduplicate IFR candidates
    seen_ifr = set()
    unique_ifr = []
    for m in ifr_candidates:
        key = (m['offset'], m['size'])
        if key not in seen_ifr:
            seen_ifr.add(key)
            unique_ifr.append(m)

    # Save reports
    reports = {
        'all_modules': all_modules,
        'setup_modules': setup_modules,
        'amd_modules': amd_modules,
        'ifr_modules': unique_ifr,
        'large_modules': large_modules,
        'raw_ifr_offsets': raw_ifr_locations[:500],  # Limit for JSON size
    }

    for name, data in reports.items():
        with open(os.path.join(OUTPUT_DIR, f'{name}.json'), 'w') as f:
            json.dump(data, f, indent=2)

    # Print summary
    print("\n" + "=" * 80)
    print(f"TOTAL MODULES FOUND: {len(all_modules)}")
    print(f"SETUP-RELATED MODULES: {len(setup_modules)}")
    print(f"AMD-RELATED MODULES: {len(amd_modules)}")
    print(f"IFR CANDIDATE MODULES: {len(unique_ifr)}")
    print(f"LARGE MODULES (>10KB): {len(large_modules)}")
    print("=" * 80)

    print("\n--- TOP 20 LARGEST MODULES ---")
    for m in sorted(large_modules, key=lambda x: x['size'], reverse=True)[:20]:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    print("\n--- SETUP MODULES ---")
    for m in setup_modules:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    print("\n--- AMD SETUP MODULES ---")
    for m in amd_modules:
        if any(kw in m['name'].lower() for kw in ['setup', 'cbs', 'pbs']):
            print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,}")

    print("\n--- IFR CANDIDATE MODULES ---")
    for m in unique_ifr[:30]:
        print(f"  {m['guid'] or 'NO-GUID':36s} | {m['name'][:40]:40s} | offset=0x{m['offset']:08X} | size={m['size']:,} | IFR@+0x{m['ifr_offset_in_module']:04X}")

    # Extract important modules
    print("\n--- EXTRACTING IMPORTANT MODULES ---")
    extracted = []
    targets = setup_modules + [m for m in amd_modules if any(kw in m['name'].lower() for kw in ['setup', 'cbs', 'pbs'])] + unique_ifr[:20]

    for m in targets:
        if m['size'] > 0:
            safe_name = m['name'].replace('/', '_').replace('\\', '_').replace(' ', '_') or 'unknown'
            filename = f"{m['offset']:08X}_{safe_name}_{m['guid'] or 'NOGUID'}_{m['size']}.bin"
            filepath = os.path.join(OUTPUT_DIR, filename)
            with open(filepath, 'wb') as f:
                f.write(rom_data[m['offset']:m['offset']+m['size']])
            extracted.append(filename)
            print(f"  Extracted: {filename}")

    print(f"\nExtracted {len(extracted)} modules to {OUTPUT_DIR}")

    # Find AMITSE and Setup module locations
    print("\n--- KEY MODULE ANALYSIS ---")
    for m in all_modules:
        if m['name'] in ['AMITSE', 'Setup', 'AMITSESetupData']:
            print(f"  KEY: {m['name']:20s} | GUID={m['guid']} | offset=0x{m['offset']:08X} | size={m['size']:,}")

if __name__ == '__main__':
    analyze_bios()
