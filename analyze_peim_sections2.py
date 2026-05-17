import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The PEIM files have sections:
# - 0x1B: Unknown (possibly a custom/AMI section)
# - 0x12: Raw section
# - 0x15: UI section (user interface name)
# - 0x14: Version section

# Let's look at the raw section (0x12) which might contain PE32 or actual data

peim_files = [
    {'offset': 0xD1BB08, 'size': 0x3592, 'name': 'SMT/DownCore'},
    {'offset': 0xD1F0A0, 'size': 0x3732, 'name': 'SMT/Downcore'},
    {'offset': 0xD467E8, 'size': 0x4445A, 'name': 'MemClk/PowerDown'},
    {'offset': 0xD9A698, 'size': 0x45E, 'name': 'IOMMU'},
    {'offset': 0xDB8B60, 'size': 0xB2A6, 'name': 'ASPM'},
    {'offset': 0xDC3E08, 'size': 0xB336, 'name': 'ASPM'},
    {'offset': 0xDCF140, 'size': 0x2D82, 'name': 'SMT/DownCore'},
    {'offset': 0xDE0490, 'size': 0x3552, 'name': 'SMT/DownCore'},
    {'offset': 0xDEB8E8, 'size': 0x5CCA, 'name': 'Above 4G/DownCore'},
    {'offset': 0xDF15B8, 'size': 0x5A52, 'name': 'Above 4G'},
]

for peim in peim_files:
    print(f"\n{'='*60}")
    print(f"PEIM: {peim['name']} at 0x{peim['offset']:X}")
    print(f"{'='*60}")
    
    peim_data = data[peim['offset']:peim['offset']+peim['size']]
    
    # Parse all sections
    sec_offset = 24
    while sec_offset < peim['size']:
        if sec_offset + 4 > peim['size']:
            break
        sec_size = peim_data[sec_offset] | (peim_data[sec_offset+1] << 8) | (peim_data[sec_offset+2] << 16)
        sec_type = peim_data[sec_offset+3]
        
        if sec_size == 0 or sec_size > peim['size'] - sec_offset:
            break
        
        print(f"  Section at 0x{sec_offset:X}: size=0x{sec_size:X}, type=0x{sec_type:02X}")
        
        # For type 0x12 (raw), check if it contains PE32
        if sec_type == 0x12 and sec_size > 100:
            raw_data = peim_data[sec_offset+4:sec_offset+sec_size]
            if raw_data[:2] == b'MZ':
                print(f"    -> Contains PE32 image")
                # Save it
                with open(f"/workspace/peim_{peim['name'].replace('/', '_')}_0x{peim['offset']:X}.bin", 'wb') as f:
                    f.write(raw_data)
            else:
                # Check for other data
                print(f"    -> Raw data, first 32 bytes: {raw_data[:32].hex()}")
        
        # For type 0x15 (UI), show the name
        if sec_type == 0x15:
            ui_data = peim_data[sec_offset+4:sec_offset+sec_size]
            try:
                ui_name = ui_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                print(f"    -> UI Name: '{ui_name}'")
            except:
                pass
        
        sec_offset += sec_size
        sec_offset = (sec_offset + 3) & ~3

