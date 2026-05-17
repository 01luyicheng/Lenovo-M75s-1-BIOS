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

# Find the largest GuidDefinedSection object
largest = None

def find_largest(obj):
    global largest
    if hasattr(obj, 'data') and obj.data:
        if largest is None or len(obj.data) > len(largest.data):
            largest = obj
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            find_largest(child)

find_largest(firmware)

if largest is None:
    print("No large object found")
    sys.exit(1)

print(f"Largest object: {type(largest).__name__}, size={len(largest.data)}")

obj_data = largest.data

# Search for HII form packages (type 0x02) more carefully
print("\nSearching for HII Form Packages:")
form_packages = []
i = 0
while i < len(obj_data) - 4:
    length = obj_data[i] | (obj_data[i+1] << 8) | (obj_data[i+2] << 16)
    pkg_type = obj_data[i+3]
    
    if pkg_type == 0x02 and length >= 0x10 and length <= len(obj_data) - i:
        if i + 4 < len(obj_data) and obj_data[i+4] == 0x01:
            form_set_len = obj_data[i+5] | (obj_data[i+6] << 8)
            if form_set_len >= 21 and form_set_len < 0x200:
                print(f"  HII Form Package at offset 0x{i:X}, len=0x{length:X}")
                form_packages.append((i, length))
                i += length
                continue
    i += 1

# Search for HII string packages (type 0x04)
print("\nSearching for HII String Packages:")
string_packages = []
i = 0
while i < len(obj_data) - 4:
    length = obj_data[i] | (obj_data[i+1] << 8) | (obj_data[i+2] << 16)
    pkg_type = obj_data[i+3]
    
    if pkg_type == 0x04 and length >= 0x10 and length <= len(obj_data) - i:
        print(f"  HII String Package at offset 0x{i:X}, len=0x{length:X}")
        string_packages.append((i, length))
        i += length
        continue
    i += 1

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

for sp_offset, sp_length in string_packages:
    parse_string_package(obj_data[sp_offset:sp_offset+sp_length])

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

