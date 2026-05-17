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

# Find the GuidDefinedSection with FV header
all_guid_sections = []

def collect_guid_sections(obj, depth=0):
    obj_type = type(obj).__name__
    if obj_type == 'GuidDefinedSection' and hasattr(obj, 'data') and obj.data:
        guid = getattr(obj, 'guid', b'')
        if isinstance(guid, bytes):
            guid_hex = guid.hex()
        else:
            guid_hex = str(guid)
        all_guid_sections.append({
            'guid': guid_hex,
            'size': len(obj.data),
            'data': obj.data,
            'obj': obj
        })
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            collect_guid_sections(child, depth + 1)

collect_guid_sections(firmware)

fv_section = None
for gs in all_guid_sections:
    if b'_FVH' in gs['data'] and len(gs['data']) > 1000000:
        fv_section = gs
        break

fv_offset_in_section = fv_section['data'].find(b'_FVH')
fv_start = fv_offset_in_section - 40
if fv_start < 0:
    fv_start = 0
fv_data = fv_section['data'][fv_start:]

fv_parser = uefi_firmware.AutoParser(fv_data)
parsed_fv = fv_parser.parse()

# Find PE32 images with HII data
def find_pe32_with_hii(obj, depth=0, results=None):
    if results is None:
        results = []
    
    if hasattr(obj, 'data') and obj.data and len(obj.data) > 1000:
        obj_type = type(obj).__name__
        name = getattr(obj, 'name', '') or ''
        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='ignore')
        elif not isinstance(name, str):
            name = str(name)
        
        if obj.data[:2] == b'MZ':
            has_hii = False
            i = 0
            while i < len(obj.data) - 4:
                length = obj.data[i] | (obj.data[i+1] << 8) | (obj.data[i+2] << 16)
                pkg_type = obj.data[i+3]
                if pkg_type in [0x02, 0x04] and length >= 0x10 and length <= len(obj.data) - i:
                    if pkg_type == 0x02 and i + 4 < len(obj.data) and obj.data[i+4] == 0x01:
                        has_hii = True
                        break
                    elif pkg_type == 0x04:
                        has_hii = True
                        break
                i += 1
            
            if has_hii:
                results.append({
                    'type': obj_type,
                    'name': name,
                    'size': len(obj.data),
                    'data': obj.data
                })
    
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            find_pe32_with_hii(child, depth + 1, results)
    
    return results

pe32_with_hii = find_pe32_with_hii(parsed_fv)
largest_pe = sorted(pe32_with_hii, key=lambda x: x['size'], reverse=True)[0]
pe_data = largest_pe['data']

# Extract all HII packages
hii_packages = []
i = 0
while i < len(pe_data) - 4:
    length = pe_data[i] | (pe_data[i+1] << 8) | (pe_data[i+2] << 16)
    pkg_type = pe_data[i+3]
    
    if pkg_type in [0x02, 0x04] and length >= 0x10 and length <= len(pe_data) - i:
        valid = False
        if pkg_type == 0x02 and i + 4 < len(pe_data) and pe_data[i+4] == 0x01:
            form_set_len = pe_data[i+5] | (pe_data[i+6] << 8)
            if form_set_len >= 21 and form_set_len < 0x200:
                valid = True
        elif pkg_type == 0x04:
            valid = True
        
        if valid:
            hii_packages.append((i, length, pkg_type))
            i += length
            continue
    i += 1

print(f"Found {len(hii_packages)} HII packages")

# Let's examine the first string package in detail
if hii_packages:
    offset, length, pkg_type = hii_packages[0]
    pkg_data = pe_data[offset:offset+length]
    print(f"\nFirst HII package at offset 0x{offset:X}, type={pkg_type}, length=0x{length:X}")
    print(f"Header bytes: {pkg_data[:16].hex()}")
    print(f"Length field: 0x{pkg_data[0] | (pkg_data[1] << 8) | (pkg_data[2] << 16):X}")
    print(f"Type field: 0x{pkg_data[3]:X}")
    
    if pkg_type == 0x04:
        # String package
        print(f"Bytes 4-20: {pkg_data[4:20].hex()}")
        print(f"Bytes 20-40: {pkg_data[20:40].hex()}")
        print(f"Bytes 40-60: {pkg_data[40:60].hex()}")
        
        # Try to find UTF-16LE strings directly
        print("\nSearching for UTF-16LE strings in package:")
        utf16_count = 0
        j = 4
        while j < length - 2:
            if pkg_data[j] != 0 and pkg_data[j+1] == 0 and 32 <= pkg_data[j] < 127:
                start = j
                while j < length - 1 and pkg_data[j] != 0 and pkg_data[j+1] == 0 and 32 <= pkg_data[j] < 127:
                    j += 2
                if j - start >= 4:
                    s = pkg_data[start:j].decode('utf-16-le', errors='ignore')
                    if len(s) >= 2:
                        utf16_count += 1
                        if utf16_count <= 20:
                            print(f"  offset 0x{start:X}: {s}")
            j += 1
        print(f"Total UTF-16LE strings found: {utf16_count}")

# Let's also look at the raw bytes of the PE32 to understand the structure
print(f"\n\nPE32 first 64 bytes:")
for j in range(0, 64, 16):
    hex_part = ' '.join(f'{b:02X}' for b in pe_data[j:j+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pe_data[j:j+16])
    print(f"  0x{j:06X}: {hex_part:<48} {ascii_part}")

