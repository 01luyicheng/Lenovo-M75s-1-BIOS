import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The strings we found are likely debug/log strings in PEIM/DXE drivers,
# not HII form strings. The actual HII form data uses string IDs that reference
# a separate string package.

# Let's search more carefully for actual IFR form data.
# In UEFI, IFR forms are in HII form packages (type 0x02).
# The package header is 4 bytes: Length(24-bit LE) + Type(8-bit)
# After the header comes the IFR opcodes.

# Let's scan the entire ROM for valid HII form packages
print("Scanning for HII Form Packages...")
form_packages = []
i = 0
while i < len(data) - 4:
    length = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
    pkg_type = data[i+3]
    
    if pkg_type == 0x02 and length >= 0x10 and length <= 0x200000 and i + length <= len(data):
        # Additional validation: check if it starts with FORM_SET (0x01)
        if i + 4 < len(data) and data[i+4] == 0x01:
            form_set_len = data[i+5] | (data[i+6] << 8)
            form_set_scope = data[i+7]
            if form_set_len >= 21 and form_set_len < 0x200 and form_set_scope == 0x01:
                form_packages.append((i, length))
                i += length
                continue
    i += 1

print(f"Found {len(form_packages)} HII Form Packages")

# Let's also search for HII String Packages (type 0x04)
print("\nScanning for HII String Packages...")
string_packages = []
i = 0
while i < len(data) - 4:
    length = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
    pkg_type = data[i+3]
    
    if pkg_type == 0x04 and length >= 0x10 and length <= 0x500000 and i + length <= len(data):
        # Validate: look for language name pattern
        # After header (4 bytes) + hdr_size (2 bytes) + string_info_offset (4 bytes) + 10 language windows (20 bytes)
        # = 30 bytes total before language name
        if i + 30 < len(data):
            lang_offset = i + 30
            # Language name should be printable ASCII
            lang_len = 0
            while lang_offset + lang_len < len(data) and lang_len < 20 and data[lang_offset + lang_len] != 0:
                lang_len += 1
            if lang_len > 0 and lang_len < 20:
                lang_name = data[lang_offset:lang_offset+lang_len].decode('ascii', errors='ignore')
                if lang_name.isalnum() or '-' in lang_name:
                    string_packages.append((i, length, lang_name))
                    i += length
                    continue
    i += 1

print(f"Found {len(string_packages)} HII String Packages")
for pkg in string_packages[:20]:
    print(f"  0x{pkg[0]:X}: length=0x{pkg[1]:X}, lang={pkg[2]}")

# Parse string packages to build string database
strings_db = {}

def parse_string_package(data, offset, length):
    pkg = data[offset:offset+length]
    if len(pkg) < 30:
        return
    
    hdr_size = struct.unpack('<H', pkg[4:6])[0]
    string_info_offset = struct.unpack('<I', pkg[6:10])[0]
    
    if string_info_offset >= len(pkg):
        return
    
    si = pkg[string_info_offset:]
    
    # Find language name
    lang_name_offset = 26  # After 10 language windows
    lang_end = lang_name_offset
    while lang_end < len(si) and si[lang_end] != 0:
        lang_end += 1
    
    if lang_end >= len(si):
        return
    
    # String blocks start after language name
    sb_offset = lang_end + 1
    
    string_id = 1
    while sb_offset < len(si):
        if sb_offset >= len(si):
            break
        block_type = si[sb_offset]
        
        if block_type == 0x00:  # End
            break
        elif block_type == 0x10:  # String block (1-byte length)
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
        elif block_type == 0x11:  # String block (2-byte length)
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
        elif block_type == 0x20:  # Duplicate block
            if sb_offset + 2 < len(si):
                dup_id = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                if dup_id in strings_db:
                    strings_db[string_id] = strings_db[dup_id]
                string_id += 1
                sb_offset += 3
            else:
                break
        elif block_type == 0x21:  # Skip block
            if sb_offset + 2 < len(si):
                skip_count = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                string_id += skip_count
                sb_offset += 3
            else:
                break
        elif block_type == 0x30:  # Font block
            if sb_offset + 2 < len(si):
                font_len = struct.unpack('<H', si[sb_offset + 1:sb_offset + 3])[0]
                sb_offset += 3 + font_len
            else:
                break
        elif block_type == 0x40:  # Extended block
            if sb_offset + 4 < len(si):
                ext_len = struct.unpack('<I', si[sb_offset + 1:sb_offset + 5])[0]
                sb_offset += 5 + ext_len
            else:
                break
        else:
            sb_offset += 1

for pkg in string_packages:
    parse_string_package(data, pkg[0], pkg[1])

print(f"\nExtracted {len(strings_db)} strings from string packages")

# Search for target keywords in string database
keywords = ['above 4g', 'iommu', 'svm', 'smt', 'downcore', 'aspm', 'pcie link', 'memory clock', 'memclk', 'power down']
found_in_strings = {}
for sid, s in strings_db.items():
    s_lower = s.lower()
    for kw in keywords:
        if kw in s_lower:
            found_in_strings[sid] = s
            print(f"String ID 0x{sid:04X}: {s}")

