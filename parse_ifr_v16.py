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

# Focus on the largest PE32 and extract all HII packages
largest_pe = sorted(pe32_with_hii, key=lambda x: x['size'], reverse=True)[0]
print(f"Largest PE32 with HII: {largest_pe['type']}/{largest_pe['name']}, size={largest_pe['size']}")

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

print(f"Found {len(hii_packages)} HII packages in largest PE32")

# Parse string packages
strings_db = {}

def parse_string_package(pkg_data):
    if len(pkg_data) < 30:
        return
    
    hdr_size = struct.unpack('<H', pkg_data[4:6])[0]
    string_info_offset = struct.unpack('<I', pkg_data[6:10])[0]
    
    if string_info_offset >= len(pkg_data):
        return
    
    si = pkg_data[string_info_offset:]
    
    # Find language name
    lang_name_offset = 26
    lang_end = lang_name_offset
    while lang_end < len(si) and si[lang_end] != 0:
        lang_end += 1
    
    if lang_end >= len(si):
        return
    
    sb_offset = lang_end + 1
    
    string_id = 1
    while sb_offset < len(si):
        if sb_offset >= len(si):
            break
        block_type = si[sb_offset]
        
        if block_type == 0x00:
            break
        elif block_type == 0x10:
            if sb_offset + 1 < len(si):
                s_len = si[sb_offset + 1]
                if sb_offset + 2 + s_len > len(si):
                    break
                s_data = si[sb_offset + 2:sb_offset + 2 + s_len]
                try:
                    s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    if s:
                        strings_db[string_id] = s
                except:
                    pass
                string_id += 1
                sb_offset += 2 + s_len
            else:
                break
        elif block_type == 0x11:
            if sb_offset + 2 < len(si):
                s_len = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                if sb_offset + 3 + s_len > len(si):
                    break
                s_data = si[sb_offset + 3:sb_offset + 3 + s_len]
                try:
                    s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                    if s:
                        strings_db[string_id] = s
                except:
                    pass
                string_id += 1
                sb_offset += 3 + s_len
            else:
                break
        elif block_type == 0x20:
            if sb_offset + 2 < len(si):
                dup_id = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                if dup_id in strings_db:
                    strings_db[string_id] = strings_db[dup_id]
                string_id += 1
                sb_offset += 3
            else:
                break
        elif block_type == 0x21:
            if sb_offset + 2 < len(si):
                skip_count = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                string_id += skip_count
                sb_offset += 3
            else:
                break
        elif block_type == 0x30:
            if sb_offset + 2 < len(si):
                font_len = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                sb_offset += 3 + font_len
            else:
                break
        elif block_type == 0x40:
            if sb_offset + 4 < len(si):
                ext_len = struct.unpack('<I', si[sb_offset + 1:sb_offset + 5])[0]
                sb_offset += 5 + ext_len
            else:
                break
        else:
            sb_offset += 1

for offset, length, pkg_type in hii_packages:
    if pkg_type == 0x04:
        parse_string_package(pe_data[offset:offset+length])

print(f"\nExtracted {len(strings_db)} strings")

# Search for target keywords
keywords = ['above 4g', 'iommu', 'svm', 'smt', 'downcore', 'aspm', 'pcie link', 'memory clock', 'memclk', 'power down']
found_in_strings = {}
for sid, s in strings_db.items():
    s_lower = s.lower()
    for kw in keywords:
        if kw in s_lower:
            found_in_strings[sid] = s
            print(f"String ID 0x{sid:04X} ({sid}): {s}")

# Save string database
with open('/workspace/strings_db.json', 'w') as f:
    json.dump(strings_db, f, indent=2)

