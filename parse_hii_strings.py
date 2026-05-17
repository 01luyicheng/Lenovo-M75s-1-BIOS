import struct
import sys
import json

# Analyze the extracted HII string packages
# The largest one is hii_pe32_0x6D78F4_pkg1_type4.bin (0xDA6850 bytes)

pkg_path = '/workspace/hii_pe32_0x6D78F4_pkg1_type4.bin'

with open(pkg_path, 'rb') as f:
    pkg_data = f.read()

print(f"Package size: {len(pkg_data)} bytes")

# HII string package header:
# EFI_HII_PACKAGE_HEADER (4 bytes): Length(24-bit) + Type(8-bit)
# Then:
#   HdrSize (2 bytes)
#   StringInfoOffset (4 bytes)
#   LanguageWindow (10 * 2 bytes = 20 bytes)
#   LanguageName (null-terminated)

length = pkg_data[0] | (pkg_data[1] << 8) | (pkg_data[2] << 16)
pkg_type = pkg_data[3]
print(f"Header length: 0x{length:X}")
print(f"Header type: 0x{pkg_type:X}")

hdr_size = struct.unpack('<H', pkg_data[4:6])[0]
string_info_offset = struct.unpack('<I', pkg_data[6:10])[0]
print(f"HdrSize: 0x{hdr_size:X}")
print(f"StringInfoOffset: 0x{string_info_offset:X}")

# Language windows
print(f"LanguageWindows: {pkg_data[10:30].hex()}")

# Language name starts at offset 30
lang_offset = 30
lang_end = lang_offset
while lang_end < len(pkg_data) and pkg_data[lang_end] != 0:
    lang_end += 1
lang_name = pkg_data[lang_offset:lang_end].decode('ascii', errors='ignore')
print(f"Language: '{lang_name}'")

# String blocks start after language name
sb_offset = lang_end + 1
print(f"String blocks start at offset: 0x{sb_offset:X}")

# Parse string blocks
strings_db = {}
string_id = 1

while sb_offset < len(pkg_data):
    if sb_offset >= len(pkg_data):
        break
    
    block_type = pkg_data[sb_offset]
    
    if block_type == 0x00:
        print(f"End block at offset 0x{sb_offset:X}")
        break
    elif block_type == 0x10:
        if sb_offset + 1 >= len(pkg_data):
            break
        s_len = pkg_data[sb_offset + 1]
        if sb_offset + 2 + s_len > len(pkg_data):
            break
        s_data = pkg_data[sb_offset + 2:sb_offset + 2 + s_len]
        try:
            s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s:
                strings_db[string_id] = s
        except:
            pass
        string_id += 1
        sb_offset += 2 + s_len
    elif block_type == 0x11:
        if sb_offset + 2 >= len(pkg_data):
            break
        s_len = struct.unpack('<H', pkg_data[sb_offset + 1:sb_offset + 3])[0]
        if sb_offset + 3 + s_len > len(pkg_data):
            break
        s_data = pkg_data[sb_offset + 3:sb_offset + 3 + s_len]
        try:
            s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
            if s:
                strings_db[string_id] = s
        except:
            pass
        string_id += 1
        sb_offset += 3 + s_len
    elif block_type == 0x20:
        if sb_offset + 2 >= len(pkg_data):
            break
        dup_id = struct.unpack('<H', pkg_data[sb_offset + 1:sb_offset + 3])[0]
        if dup_id in strings_db:
            strings_db[string_id] = strings_db[dup_id]
        string_id += 1
        sb_offset += 3
    elif block_type == 0x21:
        if sb_offset + 2 >= len(pkg_data):
            break
        skip_count = struct.unpack('<H', pkg_data[sb_offset + 1:sb_offset + 3])[0]
        string_id += skip_count
        sb_offset += 3
    elif block_type == 0x30:
        if sb_offset + 2 >= len(pkg_data):
            break
        font_len = struct.unpack('<H', pkg_data[sb_offset + 1:sb_offset + 3])[0]
        sb_offset += 3 + font_len
    elif block_type == 0x40:
        if sb_offset + 4 >= len(pkg_data):
            break
        ext_len = struct.unpack('<I', pkg_data[sb_offset + 1:sb_offset + 5])[0]
        sb_offset += 5 + ext_len
    else:
        # Unknown block type
        print(f"Unknown block type 0x{block_type:02X} at offset 0x{sb_offset:X}")
        sb_offset += 1

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

