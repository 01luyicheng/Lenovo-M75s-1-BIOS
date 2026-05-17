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

# Now let's find the Setup-related DXE drivers that contain HII data
# These are typically PE32 images with embedded HII packages

# Let's search for PE32 headers (MZ signature) in the FV objects
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
        
        # Check if it's a PE32 image
        if obj.data[:2] == b'MZ':
            # Check for HII packages inside
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
print(f"Found {len(pe32_with_hii)} PE32 images with HII data")

for pe in pe32_with_hii:
    print(f"  {pe['type']}/{pe['name']}: size={pe['size']}")

# Let's focus on the largest ones and extract HII packages
for pe in sorted(pe32_with_hii, key=lambda x: x['size'], reverse=True)[:10]:
    print(f"\nAnalyzing PE32: {pe['type']}/{pe['name']}, size={pe['size']}")
    pe_data = pe['data']
    
    # Find HII packages
    i = 0
    while i < len(pe_data) - 4:
        length = pe_data[i] | (pe_data[i+1] << 8) | (pe_data[i+2] << 16)
        pkg_type = pe_data[i+3]
        
        if pkg_type == 0x02 and length >= 0x10 and length <= len(pe_data) - i:
            if i + 4 < len(pe_data) and pe_data[i+4] == 0x01:
                form_set_len = pe_data[i+5] | (pe_data[i+6] << 8)
                if form_set_len >= 21 and form_set_len < 0x200:
                    print(f"  HII Form Package at offset 0x{i:X}, len=0x{length:X}")
                    # Save
                    safe_name = pe['name'].replace('/', '_').replace('\\', '_') or 'unknown'
                    with open(f'/workspace/form_{safe_name}_0x{i:X}.bin', 'wb') as f:
                        f.write(pe_data[i:i+length])
                    i += length
                    continue
        
        if pkg_type == 0x04 and length >= 0x10 and length <= len(pe_data) - i:
            print(f"  HII String Package at offset 0x{i:X}, len=0x{length:X}")
            safe_name = pe['name'].replace('/', '_').replace('\\', '_') or 'unknown'
            with open(f'/workspace/string_{safe_name}_0x{i:X}.bin', 'wb') as f:
                f.write(pe_data[i:i+length])
            i += length
            continue
        
        i += 1

