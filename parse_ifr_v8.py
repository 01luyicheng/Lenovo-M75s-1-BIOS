import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The FV parsing is having issues. Let's use the uefi_firmware library
# which already parsed the ROM successfully earlier.

sys.path.insert(0, '/root/.pyenv/versions/3.14.4/lib/python3.14/site-packages')
import uefi_firmware

parser = uefi_firmware.AutoParser(data)
firmware = parser.parse()

# Let's extract all objects with data and search for IFR patterns
all_objects = []

def collect_objects(obj, depth=0):
    if hasattr(obj, 'data') and obj.data and len(obj.data) > 100:
        obj_type = type(obj).__name__
        name = getattr(obj, 'name', '') or ''
        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='ignore')
        elif not isinstance(name, str):
            name = str(name)
        
        all_objects.append({
            'type': obj_type,
            'name': name,
            'size': len(obj.data),
            'data': obj.data,
            'depth': depth
        })
    
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            collect_objects(child, depth + 1)

collect_objects(firmware)
print(f"Collected {len(all_objects)} objects with data")

# Search for Setup-related objects
setup_objects = []
for obj in all_objects:
    if 'setup' in obj['name'].lower() or 'setup' in obj['type'].lower():
        setup_objects.append(obj)
        print(f"Setup object: type={obj['type']}, name={obj['name']}, size={obj['size']}")

# Also search for objects containing our target strings
print("\n\nSearching for objects containing target strings:")
targets = [
    b'Above 4G Decoding', b'Above4G', b'Above 4G',
    b'IOMMU', b'Iommu',
    b'SVM Mode', b'SVM mode', b'SVM',
    b'SMT Mode', b'SMT mode', b'SMT',
    b'Downcore', b'DownCore', b'Down Core',
    b'ASPM',
    b'PCIe Link Speed', b'PCIe Speed', b'Link Speed',
    b'Memory Clock', b'MemClk', b'Mem Clk',
    b'Power Down Mode', b'PowerDown', b'Power Down'
]

found_objects = {}
for obj in all_objects:
    for target in targets:
        if target in obj['data']:
            key = f"{obj['type']}_{obj['name']}_{obj['size']}"
            if key not in found_objects:
                found_objects[key] = {'obj': obj, 'targets': []}
            found_objects[key]['targets'].append(target.decode('latin-1', errors='ignore'))

for key, info in found_objects.items():
    obj = info['obj']
    print(f"\nObject: type={obj['type']}, name={obj['name']}, size={obj['size']}")
    print(f"  Found strings: {', '.join(info['targets'])}")

# Now let's try to find the actual HII form/string packages within these objects
# The IFR data might be in PE/COFF sections

print("\n\nSearching for HII packages within objects:")
for obj in all_objects:
    obj_data = obj['data']
    # Search for HII package headers
    i = 0
    while i < len(obj_data) - 4:
        length = obj_data[i] | (obj_data[i+1] << 8) | (obj_data[i+2] << 16)
        pkg_type = obj_data[i+3]
        
        if pkg_type == 0x02 and length >= 0x10 and length <= len(obj_data) - i:
            if i + 4 < len(obj_data) and obj_data[i+4] == 0x01:
                form_set_len = obj_data[i+5] | (obj_data[i+6] << 8)
                if form_set_len >= 21 and form_set_len < 0x200:
                    print(f"  HII Form Package in {obj['type']}/{obj['name']} at offset 0x{i:X}, len=0x{length:X}")
                    break
        
        if pkg_type == 0x04 and length >= 0x10 and length <= len(obj_data) - i:
            print(f"  HII String Package in {obj['type']}/{obj['name']} at offset 0x{i:X}, len=0x{length:X}")
            break
        
        i += 1

