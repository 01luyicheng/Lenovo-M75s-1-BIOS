import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

sys.path.insert(0, '/root/.pyenv/versions/3.14.4/lib/python3.14/site-packages')
import uefi_firmware

parser = uefi_firmware.AutoParser(data)
firmware = parser.parse()

# Find the largest objects that contain our target strings - these are likely
# the Setup DXE drivers with embedded HII data

all_objects = []
def collect_objects(obj, depth=0):
    if hasattr(obj, 'data') and obj.data and len(obj.data) > 1000:
        obj_type = type(obj).__name__
        name = getattr(obj, 'name', '') or ''
        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='ignore')
        elif not isinstance(name, str):
            name = str(name)
        
        # Check for target strings
        has_targets = False
        targets_found = []
        for target in [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']:
            if target in obj.data:
                targets_found.append(target.decode('latin-1'))
                has_targets = True
        
        if has_targets:
            all_objects.append({
                'type': obj_type,
                'name': name,
                'size': len(obj.data),
                'data': obj.data,
                'targets': targets_found,
                'depth': depth
            })
    
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            collect_objects(child, depth + 1)

collect_objects(firmware)

# Sort by size (largest first)
all_objects.sort(key=lambda x: x['size'], reverse=True)

print(f"Found {len(all_objects)} objects with target strings")
for obj in all_objects[:20]:
    print(f"  {obj['type']}/{obj['name']}: size={obj['size']}, targets={obj['targets']}")

# Let's focus on the largest objects - these likely contain the Setup IFR data
# Save the largest one for detailed analysis
if all_objects:
    largest = all_objects[0]
    print(f"\nAnalyzing largest object: {largest['type']}/{largest['name']}, size={largest['size']}")
    
    obj_data = largest['data']
    
    # Search for HII form packages within this object
    print("\nSearching for HII packages:")
    i = 0
    while i < len(obj_data) - 4:
        length = obj_data[i] | (obj_data[i+1] << 8) | (obj_data[i+2] << 16)
        pkg_type = obj_data[i+3]
        
        if pkg_type == 0x02 and length >= 0x10 and length <= len(obj_data) - i:
            if i + 4 < len(obj_data) and obj_data[i+4] == 0x01:
                form_set_len = obj_data[i+5] | (obj_data[i+6] << 8)
                if form_set_len >= 21 and form_set_len < 0x200:
                    print(f"  HII Form Package at offset 0x{i:X}, len=0x{length:X}")
                    # Extract and save
                    with open(f'/workspace/form_pkg_0x{i:X}.bin', 'wb') as f:
                        f.write(obj_data[i:i+length])
                    i += length
                    continue
        
        if pkg_type == 0x04 and length >= 0x10 and length <= len(obj_data) - i:
            print(f"  HII String Package at offset 0x{i:X}, len=0x{length:X}")
            with open(f'/workspace/string_pkg_0x{i:X}.bin', 'wb') as f:
                f.write(obj_data[i:i+length])
            i += length
            continue
        
        i += 1

