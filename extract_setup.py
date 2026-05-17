#!/usr/bin/env python3
"""
Advanced BIOS Setup Module Extractor
Extracts PE32 images and searches for IFR data within Setup modules
"""

import sys
import os
import struct
from uefi_firmware import *

ROM_PATH = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"
OUTPUT_DIR = "/workspace/bios_analysis/extracted"

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def guid_to_str(guid_bytes):
    if len(guid_bytes) != 16:
        return "INVALID"
    g1 = struct.unpack('<I', guid_bytes[0:4])[0]
    g2 = struct.unpack('<H', guid_bytes[4:6])[0]
    g3 = struct.unpack('<H', guid_bytes[6:8])[0]
    g4 = guid_bytes[8:10]
    g5 = guid_bytes[10:16]
    return f"{g1:08X}-{g2:04X}-{g3:04X}-{g4.hex().upper()}-{g5.hex().upper()}"

def find_ifr_in_data(data, base_offset=0):
    """Search for IFR opcodes in binary data"""
    ifr_signatures = [
        b'\x01\x8E',  # EFI_IFR_FORM_SET opcodes
        b'\x0E\x00',  # EFI_IFR_FORM_SET (alternative)
    ]
    
    # Look for HII/IFR signatures
    # IFR typically starts with EFI_IFR_FORM_SET (0x0E 0x86 or similar)
    results = []
    
    # Search for common IFR patterns
    for i in range(len(data) - 4):
        # EFI_IFR_FORM_SET opcode: 0x0E followed by length
        if data[i] == 0x0E and data[i+1] in [0x86, 0x8E]:
            # Check for reasonable length
            length = struct.unpack('<H', data[i+2:i+4])[0] if i+3 < len(data) else 0
            if 0 < length < 0x10000:
                results.append((base_offset + i, length, "EFI_IFR_FORM_SET"))
        
        # Alternative: look for GUID patterns that indicate IFR packages
        if i + 16 <= len(data):
            guid_bytes = data[i:i+16]
            # Check for known HII package GUIDs
            if guid_bytes[0:4] == b'\xD9\x54\x93\x7E':  # EFI_HII_PACKAGE_FORM
                results.append((base_offset + i, 16, "HII_PACKAGE_FORM_GUID"))
    
    return results

def extract_pe32(data, output_path):
    """Extract PE32 image from raw section data"""
    # PE32 signature: 'MZ' at start, 'PE\0\0' at offset from MZ header
    if len(data) < 64:
        return False
    
    if data[0:2] != b'MZ':
        return False
    
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if pe_offset + 4 > len(data):
        return False
    
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        return False
    
    with open(output_path, 'wb') as f:
        f.write(data)
    return True

def analyze_firmware():
    print("=" * 80)
    print("Advanced Setup Module Extractor")
    print("=" * 80)
    
    with open(ROM_PATH, 'rb') as f:
        raw_data = f.read()
    
    print(f"File size: {len(raw_data)} bytes ({len(raw_data)/1024/1024:.2f} MB)")
    ensure_dir(OUTPUT_DIR)
    
    parser = AutoParser(raw_data)
    if parser.type() is None:
        print("ERROR: Could not identify firmware type")
        return
    
    print(f"Detected firmware type: {parser.type()}")
    firmware = parser.parse()
    
    # Key Setup modules to extract
    target_guids = [
        '899407D7-99FE-43D8-9A21-79EC328CAC21',  # AMITSE/Setup
        'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A',  # AMITSESetupData
        'EE4E5898-3914-4259-9D6E-DC7BD79403CF',  # AMITSE/AMITSESetupData
        'A59A0056-3341-44B5-9F89-379D6D011A73',  # SetupUtility
    ]
    
    extracted = {
        'pe32': [],
        'ifr': [],
        'setup_modules': []
    }
    
    def process_object(obj, depth=0):
        indent = "  " * depth
        obj_type = type(obj).__name__
        
        guid = None
        if hasattr(obj, 'guid'):
            if isinstance(obj.guid, bytes) and len(obj.guid) == 16:
                guid = guid_to_str(obj.guid)
            elif isinstance(obj.guid, str):
                guid = obj.guid
        
        name = ""
        if hasattr(obj, 'name') and isinstance(obj.name, str):
            name = obj.name
        
        offset = 0
        if hasattr(obj, 'offset'):
            offset = obj.offset
        
        data = None
        if hasattr(obj, 'data') and obj.data:
            data = obj.data
        
        # Check if this is a target module
        is_target = False
        if guid and guid.upper() in [g.upper() for g in target_guids]:
            is_target = True
        if name and any(kw in name.lower() for kw in ['setup', 'amitse', 'tse']):
            is_target = True
        
        if is_target and data:
            print(f"\n{indent}[TARGET] {name} - {obj_type}")
            print(f"{indent}  GUID: {guid}")
            print(f"{indent}  Offset: 0x{offset:08X}, Size: 0x{len(data):08X}")
            
            # Save raw data
            safe_name = name.replace('/', '_').replace('\\', '_').replace(' ', '_') if name else f"module_{offset:08X}"
            raw_path = os.path.join(OUTPUT_DIR, f"{safe_name}_RAW.bin")
            with open(raw_path, 'wb') as f:
                f.write(data)
            print(f"{indent}  [SAVED RAW] {raw_path}")
            
            # Try to extract PE32
            pe32_path = os.path.join(OUTPUT_DIR, f"{safe_name}_PE32.efi")
            if extract_pe32(data, pe32_path):
                print(f"{indent}  [EXTRACTED PE32] {pe32_path}")
                extracted['pe32'].append({
                    'name': name,
                    'guid': guid,
                    'path': pe32_path,
                    'offset': offset,
                    'size': len(data)
                })
            
            # Search for IFR data
            ifr_results = find_ifr_in_data(data, offset)
            if ifr_results:
                print(f"{indent}  [IFR FOUND] {len(ifr_results)} potential IFR locations:")
                for ifr_offset, ifr_size, ifr_type in ifr_results[:5]:  # Show first 5
                    print(f"{indent}    - {ifr_type} at offset 0x{ifr_offset:08X}, size 0x{ifr_size:04X}")
                    extracted['ifr'].append({
                        'name': name,
                        'guid': guid,
                        'offset': ifr_offset,
                        'size': ifr_size,
                        'type': ifr_type
                    })
            
            extracted['setup_modules'].append({
                'name': name,
                'guid': guid,
                'type': obj_type,
                'offset': offset,
                'size': len(data)
            })
        
        # Process children
        if hasattr(obj, 'objects') and obj.objects:
            for child in obj.objects:
                process_object(child, depth + 1)
    
    print("\n[Extracting target modules...]")
    process_object(firmware)
    
    # Also do a raw search for IFR across the entire ROM
    print("\n[Raw IFR search across entire ROM...]")
    raw_ifr = find_ifr_in_data(raw_data)
    print(f"Found {len(raw_ifr)} potential IFR locations in raw ROM")
    
    # Print summary
    print("\n" + "=" * 80)
    print("EXTRACTION SUMMARY")
    print("=" * 80)
    print(f"\nSetup modules extracted: {len(extracted['setup_modules'])}")
    for mod in extracted['setup_modules']:
        print(f"  - {mod['name']} ({mod['guid']})")
        print(f"    Offset: 0x{mod['offset']:08X}, Size: {mod['size']} bytes")
    
    print(f"\nPE32 images extracted: {len(extracted['pe32'])}")
    for pe in extracted['pe32']:
        print(f"  - {pe['path']}")
    
    print(f"\nIFR locations found: {len(extracted['ifr'])}")
    for ifr in extracted['ifr']:
        print(f"  - {ifr['name']}: {ifr['type']} at 0x{ifr['offset']:08X}")
    
    print(f"\nAll extracted files saved to: {OUTPUT_DIR}")
    
    return extracted

if __name__ == '__main__':
    analyze_firmware()
