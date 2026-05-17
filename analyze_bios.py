#!/usr/bin/env python3
"""
BIOS Firmware Analysis Script using uefi_firmware
Analyzes IMAGEM2C.rom AMI Aptio BIOS
"""

import sys
import os
import json
import struct
from uefi_firmware import *

ROM_PATH = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"
OUTPUT_DIR = "/workspace/bios_analysis"

def ensure_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)

def guid_to_str(guid_bytes):
    """Convert GUID bytes to standard string format"""
    if len(guid_bytes) != 16:
        return "INVALID"
    g1 = struct.unpack('<I', guid_bytes[0:4])[0]
    g2 = struct.unpack('<H', guid_bytes[4:6])[0]
    g3 = struct.unpack('<H', guid_bytes[6:8])[0]
    g4 = guid_bytes[8:10]
    g5 = guid_bytes[10:16]
    return f"{g1:08X}-{g2:04X}-{g3:04X}-{g4.hex().upper()}-{g5.hex().upper()}"

def analyze_firmware():
    print("=" * 80)
    print("UEFI Firmware Analysis - IMAGEM2C.rom")
    print("=" * 80)
    
    with open(ROM_PATH, 'rb') as f:
        data = f.read()
    
    print(f"File size: {len(data)} bytes ({len(data)/1024/1024:.2f} MB)")
    print(f"Output directory: {OUTPUT_DIR}")
    ensure_dir(OUTPUT_DIR)
    
    print("\n[1] Parsing firmware image...")
    parser = AutoParser(data)
    if parser.type() is None:
        print("ERROR: Could not identify firmware type")
        return
    
    print(f"Detected firmware type: {parser.type()}")
    firmware = parser.parse()
    
    firmware_volumes = []
    setup_modules = []
    nvram_regions = []
    all_modules = []
    pe32_sections = []
    ifr_sections = []
    
    def safe_name(obj):
        if hasattr(obj, 'name'):
            if isinstance(obj.name, str):
                return obj.name
            elif isinstance(obj.name, int):
                return str(obj.name)
            elif obj.name is None:
                return ""
            else:
                return str(obj.name)
        return ""
    
    def process_object(obj, path="", depth=0):
        indent = "  " * depth
        obj_type = type(obj).__name__
        
        guid = None
        if hasattr(obj, 'guid'):
            if isinstance(obj.guid, bytes) and len(obj.guid) == 16:
                guid = guid_to_str(obj.guid)
            elif isinstance(obj.guid, str):
                guid = obj.guid
        
        name = safe_name(obj)
        
        offset = 0
        if hasattr(obj, 'offset'):
            offset = obj.offset
        
        size = 0
        if hasattr(obj, 'size'):
            size = obj.size
        elif hasattr(obj, 'data') and obj.data:
            size = len(obj.data)
        
        info = {
            'type': obj_type,
            'guid': guid,
            'name': name,
            'offset': offset,
            'size': size,
            'path': path
        }
        
        # Firmware Volume detection
        if obj_type == 'FirmwareVolume':
            fv_info = {
                'guid': guid,
                'offset': offset,
                'size': size,
                'name': name
            }
            if hasattr(obj, 'fv_guid'):
                if isinstance(obj.fv_guid, bytes) and len(obj.fv_guid) == 16:
                    fv_info['fv_guid'] = guid_to_str(obj.fv_guid)
                else:
                    fv_info['fv_guid'] = str(obj.fv_guid)
            firmware_volumes.append(fv_info)
            print(f"{indent}[FV] Offset: 0x{offset:08X}, Size: 0x{size:08X} ({size/1024:.1f} KB)")
            if guid:
                print(f"{indent}     GUID: {guid}")
            if fv_info.get('fv_guid'):
                print(f"{indent}     FV GUID: {fv_info['fv_guid']}")
        
        # NVRAM detection
        name_lower = name.lower() if isinstance(name, str) else ""
        if 'NVRAM' in obj_type or 'nvram' in name_lower or 'variable' in name_lower:
            nvram_info = {
                'type': obj_type,
                'guid': guid,
                'offset': offset,
                'size': size,
                'name': name
            }
            nvram_regions.append(nvram_info)
            print(f"{indent}[NVRAM] {name} - Offset: 0x{offset:08X}, Size: 0x{size:08X}")
        
        # Setup-related modules detection
        setup_keywords = ['setup', 'tse', 'amitse', 'amdsetup', 'biossetup', 'setuputility', 
                         'setupdata', 'ifrextract', 'hii', 'form', 'amdpsptool',
                         'amitsesetup', 'setupmenu', 'biosconfig', 'amdsetupdxe',
                         'setupbrowser', 'platformsetup']
        is_setup = False
        for kw in setup_keywords:
            if kw in name_lower:
                is_setup = True
                break
        
        setup_guids = [
            '899407D7-99FE-43D8-9A21-79EC328CAC21',
            'A59A0056-3341-44B5-9F89-379D6D011A73',
            'B1DA0ADF-4F77-4070-A88E-BFFE1C60529A',
        ]
        if guid and any(g in guid.upper() for g in setup_guids):
            is_setup = True
        
        if is_setup:
            setup_info = {
                'type': obj_type,
                'guid': guid,
                'offset': offset,
                'size': size,
                'name': name,
                'path': path
            }
            setup_modules.append(setup_info)
            print(f"{indent}[SETUP] {name} - Type: {obj_type}")
            print(f"{indent}        GUID: {guid}, Offset: 0x{offset:08X}, Size: 0x{size:08X}")
        
        # PE32 section detection
        if 'PE32' in obj_type or 'pe32' in name_lower:
            pe32_sections.append(info)
        
        # IFR/Form detection
        if 'ifr' in name_lower or 'form' in name_lower or 'hii' in name_lower:
            ifr_sections.append(info)
        
        if 'File' in obj_type or 'Section' in obj_type:
            all_modules.append(info)
        
        # Process children
        if hasattr(obj, 'objects') and obj.objects:
            for i, child in enumerate(obj.objects):
                child_path = f"{path}/{obj_type}[{i}]"
                process_object(child, child_path, depth + 1)
        
        # Extract setup modules
        if is_setup and hasattr(obj, 'data') and obj.data:
            safe_name_str = name.replace('/', '_').replace('\\', '_').replace(' ', '_') if name else f"setup_{offset:08X}"
            extract_path = os.path.join(OUTPUT_DIR, f"{safe_name_str}_{offset:08X}.bin")
            try:
                with open(extract_path, 'wb') as ef:
                    ef.write(obj.data)
                print(f"{indent}        [EXTRACTED] -> {extract_path}")
            except Exception as e:
                print(f"{indent}        [ERROR extracting] {e}")
    
    print("\n[2] Traversing firmware structure...")
    process_object(firmware)
    
    print("\n[3] Saving analysis results...")
    
    results = {
        'file': ROM_PATH,
        'size': len(data),
        'firmware_volumes': firmware_volumes,
        'setup_modules': setup_modules,
        'nvram_regions': nvram_regions,
        'pe32_sections': pe32_sections,
        'ifr_sections': ifr_sections,
        'all_modules_count': len(all_modules)
    }
    
    results_path = os.path.join(OUTPUT_DIR, 'analysis_results.json')
    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to: {results_path}")
    
    # Print summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nFirmware Volumes found: {len(firmware_volumes)}")
    for fv in firmware_volumes:
        print(f"  - Offset: 0x{fv['offset']:08X}, Size: 0x{fv['size']:08X} ({fv['size']/1024/1024:.2f} MB)")
        if fv.get('guid'):
            print(f"    GUID: {fv['guid']}")
        if fv.get('fv_guid'):
            print(f"    FV GUID: {fv['fv_guid']}")
    
    print(f"\nSetup-related modules found: {len(setup_modules)}")
    for mod in setup_modules:
        print(f"  - {mod['name']}")
        print(f"    Type: {mod['type']}, GUID: {mod['guid']}")
        print(f"    Offset: 0x{mod['offset']:08X}, Size: 0x{mod['size']:08X} ({mod['size']/1024:.1f} KB)")
    
    print(f"\nNVRAM regions found: {len(nvram_regions)}")
    for nv in nvram_regions:
        print(f"  - {nv['name']} - Offset: 0x{nv['offset']:08X}, Size: 0x{nv['size']:08X}")
    
    print(f"\nPE32 sections found: {len(pe32_sections)}")
    print(f"IFR/Form sections found: {len(ifr_sections)}")
    print(f"\nTotal modules scanned: {len(all_modules)}")
    print(f"\nExtracted files saved to: {OUTPUT_DIR}")
    
    return results

if __name__ == '__main__':
    analyze_firmware()
