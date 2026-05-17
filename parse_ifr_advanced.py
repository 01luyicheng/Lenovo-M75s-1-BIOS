import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# HII String Package format:
# EFI_HII_PACKAGE_HEADER (4 bytes): Length(24 bits) + Type(8 bits)
# Type 0x04 = EFI_HII_PACKAGE_STRINGS
# Then:HdrSize(2) + StringInfoOffset(4) + LanguageWindow(10*2) + LanguageName

# HII Form Package format:
# EFI_HII_PACKAGE_HEADER (4 bytes): Length(24 bits) + Type(8 bits)  
# Type 0x02 = EFI_HII_PACKAGE_FORMS

# Let's find all string packages and build a string database

def find_hii_packages(data):
    packages = []
    i = 0
    while i < len(data) - 4:
        length = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
        pkg_type = data[i+3]
        if length > 4 and length < 0x200000 and i + length <= len(data):
            if pkg_type in [0x02, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20]:
                packages.append((i, length, pkg_type))
                i += length
                continue
        i += 1
    return packages

# Actually, let's just search for the HII package signature pattern
# String packages often start with language names like "en-US" or "en"
def find_string_packages(data):
    packages = []
    # Search for common language patterns near package headers
    for lang in [b'en-US\x00', b'en\x00', b'zh-Hans\x00', b'zh-Hant\x00', b'fr-FR\x00']:
        idx = 0
        while True:
            idx = data.find(lang, idx)
            if idx == -1:
                break
            # Look backwards for package header
            for back in range(4, 64):
                if idx - back >= 0:
                    hdr_pos = idx - back
                    length = data[hdr_pos] | (data[hdr_pos+1] << 8) | (data[hdr_pos+2] << 16)
                    pkg_type = data[hdr_pos+3]
                    if pkg_type == 0x04 and length > 0x10 and length < 0x200000 and hdr_pos + length <= len(data):
                        packages.append((hdr_pos, length, pkg_type, lang.decode('latin-1').strip('\x00')))
                        break
            idx += 1
    return packages

string_pkgs = find_string_packages(data)
print(f"Found {len(string_pkgs)} string packages")

# Build string database
strings_db = {}  # offset -> string

def parse_string_package(data, offset, length):
    """Parse HII string package and extract strings"""
    pkg = data[offset:offset+length]
    if len(pkg) < 8:
        return
    
    hdr_size = struct.unpack('<H', pkg[4:6])[0]
    string_info_offset = struct.unpack('<I', pkg[6:10])[0]
    
    # Skip to string info
    si = pkg[string_info_offset:]
    if len(si) < 4:
        return
    
    # LanguageName is null-terminated at offset 26 (after 10 language windows)
    lang_name_offset = 26
    # Find language name
    lang_end = lang_name_offset
    while lang_end < len(si) and si[lang_end] != 0:
        lang_end += 1
    lang_name = si[lang_name_offset:lang_end].decode('latin-1', errors='ignore')
    
    # String blocks start after language name + null
    sb_offset = lang_end + 1
    
    string_id = 1
    while sb_offset < len(si):
        block_type = si[sb_offset]
        if block_type == 0x00:  # End
            break
        elif block_type == 0x10:  # String block (1-byte length)
            if sb_offset + 1 < len(si):
                s_len = si[sb_offset + 1]
                s_data = si[sb_offset + 2:sb_offset + 2 + s_len]
                try:
                    s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
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
                s_data = si[sb_offset + 3:sb_offset + 3 + s_len]
                try:
                    s = s_data.decode('utf-16-le', errors='ignore').rstrip('\x00')
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
            # Unknown block, try to skip
            sb_offset += 1

for pkg in string_pkgs:
    parse_string_package(data, pkg[0], pkg[1])

print(f"Extracted {len(strings_db)} strings")

# Search for our keywords in the string database
keywords = ['Above 4G Decoding', 'Above4G', 'Above 4G', 'IOMMU', 'SVM Mode', 'SVM mode', 'SMT Mode', 'SMT mode', 'Downcore', 'DownCore', 'Down Core', 'ASPM', 'PCIe Link Speed', 'Memory Clock', 'MemClk', 'Power Down Mode', 'PowerDown', 'Power Down']

found_strings = {}
for sid, s in strings_db.items():
    for kw in keywords:
        if kw.lower() in s.lower():
            found_strings[sid] = s
            print(f"String ID 0x{sid:04X}: {s}")

# Now search for form packages and parse IFR
form_packages = []
i = 0
while i < len(data) - 4:
    length = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
    pkg_type = data[i+3]
    if pkg_type == 0x02 and length > 4 and length < 0x200000 and i + length <= len(data):
        # Check if starts with FORM_SET
        if i + 4 < len(data) and data[i+4] == 0x01:
            form_packages.append((i, length))
            i += length
            continue
    i += 1

print(f"\nFound {len(form_packages)} form packages")

# Parse IFR from form packages
def parse_ifr(data, offset, length, strings_db):
    """Parse IFR opcodes from a form package"""
    pkg = data[offset:offset+length]
    pos = 4  # Skip header
    
    results = []
    scope_stack = []
    
    while pos < len(pkg):
        if pos + 3 > len(pkg):
            break
            
        opcode = pkg[pos]
        op_length = pkg[pos+1] | (pkg[pos+2] << 8)
        
        if op_length == 0 or pos + op_length > len(pkg):
            pos += 1
            continue
        
        op_data = pkg[pos:pos+op_length]
        
        # Parse specific opcodes
        if opcode == 0x01:  # FORM_SET
            if len(op_data) >= 21:
                guid = op_data[4:20]
                title_id = struct.unpack('<H', op_data[20:22])[0] if len(op_data) >= 22 else 0
                title = strings_db.get(title_id, f"ID_0x{title_id:04X}")
                results.append({
                    'offset': offset + pos,
                    'opcode': 'FORM_SET',
                    'title': title,
                    'guid': guid.hex()
                })
                scope_stack.append('FORM_SET')
        
        elif opcode == 0x02:  # FORM
            if len(op_data) >= 8:
                form_id = struct.unpack('<H', op_data[4:6])[0] if len(op_data) >= 6 else 0
                title_id = struct.unpack('<H', op_data[6:8])[0] if len(op_data) >= 8 else 0
                title = strings_db.get(title_id, f"ID_0x{title_id:04X}")
                results.append({
                    'offset': offset + pos,
                    'opcode': 'FORM',
                    'form_id': form_id,
                    'title': title
                })
                scope_stack.append('FORM')
        
        elif opcode == 0x05:  # ONE_OF
            if len(op_data) >= 14:
                prompt_id = struct.unpack('<H', op_data[4:6])[0]
                help_id = struct.unpack('<H', op_data[6:8])[0]
                varstore_id = struct.unpack('<H', op_data[10:12])[0] if len(op_data) >= 12 else 0
                var_offset = struct.unpack('<H', op_data[12:14])[0] if len(op_data) >= 14 else 0
                prompt = strings_db.get(prompt_id, f"ID_0x{prompt_id:04X}")
                results.append({
                    'offset': offset + pos,
                    'opcode': 'ONE_OF',
                    'prompt': prompt,
                    'varstore_id': varstore_id,
                    'var_offset': var_offset
                })
                scope_stack.append('ONE_OF')
        
        elif opcode == 0x06:  # CHECKBOX
            if len(op_data) >= 14:
                prompt_id = struct.unpack('<H', op_data[4:6])[0]
                help_id = struct.unpack('<H', op_data[6:8])[0]
                varstore_id = struct.unpack('<H', op_data[10:12])[0] if len(op_data) >= 12 else 0
                var_offset = struct.unpack('<H', op_data[12:14])[0] if len(op_data) >= 14 else 0
                prompt = strings_db.get(prompt_id, f"ID_0x{prompt_id:04X}")
                results.append({
                    'offset': offset + pos,
                    'opcode': 'CHECKBOX',
                    'prompt': prompt,
                    'varstore_id': varstore_id,
                    'var_offset': var_offset
                })
                scope_stack.append('CHECKBOX')
        
        elif opcode == 0x07:  # NUMERIC
            if len(op_data) >= 18:
                prompt_id = struct.unpack('<H', op_data[4:6])[0]
                help_id = struct.unpack('<H', op_data[6:8])[0]
                varstore_id = struct.unpack('<H', op_data[10:12])[0] if len(op_data) >= 12 else 0
                var_offset = struct.unpack('<H', op_data[12:14])[0] if len(op_data) >= 14 else 0
                prompt = strings_db.get(prompt_id, f"ID_0x{prompt_id:04X}")
                results.append({
                    'offset': offset + pos,
                    'opcode': 'NUMERIC',
                    'prompt': prompt,
                    'varstore_id': varstore_id,
                    'var_offset': var_offset
                })
                scope_stack.append('NUMERIC')
        
        elif opcode == 0x0A:  # SUPPRESS_IF
            results.append({
                'offset': offset + pos,
                'opcode': 'SUPPRESS_IF',
                'scope_depth': len(scope_stack)
            })
            scope_stack.append('SUPPRESS_IF')
        
        elif opcode == 0x19:  # GRAY_OUT_IF (actually 0x19 is VARSTORE_NAME_VALUE in some specs, let me check)
            # In EDK2: EFI_IFR_GRAY_OUT_IF = 0x19
            results.append({
                'offset': offset + pos,
                'opcode': 'GRAY_OUT_IF',
                'scope_depth': len(scope_stack)
            })
            scope_stack.append('GRAY_OUT_IF')
        
        elif opcode == 0x18:  # VARSTORE
            if len(op_data) >= 24:
                guid = op_data[4:20]
                varstore_id = struct.unpack('<H', op_data[20:22])[0] if len(op_data) >= 22 else 0
                size = struct.unpack('<H', op_data[22:24])[0] if len(op_data) >= 24 else 0
                name = b''
                if len(op_data) > 24:
                    name_end = 24
                    while name_end < len(op_data) and op_data[name_end] != 0:
                        name_end += 1
                    name = op_data[24:name_end]
                results.append({
                    'offset': offset + pos,
                    'opcode': 'VARSTORE',
                    'varstore_id': varstore_id,
                    'size': size,
                    'name': name.decode('latin-1', errors='ignore'),
                    'guid': guid.hex()
                })
        
        elif opcode == 0x1A:  # VARSTORE_EFI
            if len(op_data) >= 24:
                guid = op_data[4:20]
                varstore_id = struct.unpack('<H', op_data[20:22])[0] if len(op_data) >= 22 else 0
                size = struct.unpack('<H', op_data[22:24])[0] if len(op_data) >= 24 else 0
                name = b''
                if len(op_data) > 24:
                    name_end = 24
                    while name_end < len(op_data) and op_data[name_end] != 0:
                        name_end += 1
                    name = op_data[24:name_end]
                results.append({
                    'offset': offset + pos,
                    'opcode': 'VARSTORE_EFI',
                    'varstore_id': varstore_id,
                    'size': size,
                    'name': name.decode('latin-1', errors='ignore'),
                    'guid': guid.hex()
                })
        
        elif opcode == 0x1C:  # END
            if scope_stack:
                scope_stack.pop()
            results.append({
                'offset': offset + pos,
                'opcode': 'END',
                'scope_depth': len(scope_stack)
            })
        
        pos += op_length
    
    return results

# Parse all form packages
all_ifr = []
for fp_offset, fp_length in form_packages[:10]:  # Limit to first 10
    print(f"\nParsing form package at 0x{fp_offset:X}, length {fp_length}")
    ifr = parse_ifr(data, fp_offset, fp_length, strings_db)
    all_ifr.extend(ifr)
    print(f"  Found {len(ifr)} IFR opcodes")

# Search for our target settings in parsed IFR
target_keywords = ['above 4g', 'iommu', 'svm', 'smt', 'downcore', 'aspm', 'pcie link', 'memory clock', 'memclk', 'power down']
print(f"\n\nSearching parsed IFR for target settings...")
for item in all_ifr:
    prompt = item.get('prompt', '')
    if prompt:
        prompt_lower = prompt.lower()
        for kw in target_keywords:
            if kw in prompt_lower:
                print(f"\nFound '{kw}' in IFR at 0x{item['offset']:X}:")
                print(f"  Opcode: {item['opcode']}")
                print(f"  Prompt: {prompt}")
                if 'varstore_id' in item:
                    print(f"  VarStore ID: 0x{item['varstore_id']:04X}")
                if 'var_offset' in item:
                    print(f"  VarOffset: 0x{item['var_offset']:04X}")

