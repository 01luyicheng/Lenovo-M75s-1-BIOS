import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# We found 6 valid PE images. Let's analyze them for HII data.
# The PE images are at:
# 0x77094, 0x6D015C, 0x6D78F4, 0x1077094, 0x141215C, 0x14198F4

pe_positions = [0x77094, 0x6D015C, 0x6D78F4, 0x1077094, 0x141215C, 0x14198F4]

targets = [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']

for pe_pos in pe_positions:
    print(f"\n{'='*60}")
    print(f"PE32 at 0x{pe_pos:X}")
    print(f"{'='*60}")
    
    # Get PE size
    pe_offset = struct.unpack('<I', data[pe_pos+0x3C:pe_pos+0x3C+4])[0]
    oh_offset = pe_pos + pe_offset + 24
    magic = struct.unpack('<H', data[oh_offset:oh_offset+2])[0]
    if magic == 0x10b:
        size_of_image_offset = oh_offset + 0x38
    elif magic == 0x20b:
        size_of_image_offset = oh_offset + 0x44
    else:
        print(f"  Unknown magic: 0x{magic:04X}")
        continue
    
    size_of_image = struct.unpack('<I', data[size_of_image_offset:size_of_image_offset+4])[0]
    pe_end = pe_pos + size_of_image
    
    if pe_end > len(data):
        pe_end = len(data)
    
    pe_data = data[pe_pos:pe_end]
    print(f"  Size: 0x{len(pe_data):X}")
    
    # Check for target strings
    found_targets = []
    for target in targets:
        if target in pe_data:
            found_targets.append(target.decode('latin-1'))
    
    if found_targets:
        print(f"  Target strings: {found_targets}")
    
    # Search for HII packages
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
    
    print(f"  HII packages: {len(hii_packages)}")
    for pkg in hii_packages[:10]:
        print(f"    offset=0x{pkg[0]:X}, length=0x{pkg[1]:X}, type={pkg[2]}")
    
    # If this PE has HII packages, save it
    if hii_packages:
        with open(f'/workspace/pe32_0x{pe_pos:X}.bin', 'wb') as f:
            f.write(pe_data)
        print(f"  Saved to /workspace/pe32_0x{pe_pos:X}.bin")
        
        # Also extract HII packages
        for idx, (offset, length, pkg_type) in enumerate(hii_packages):
            pkg_data = pe_data[offset:offset+length]
            pkg_name = f'hii_pe32_0x{pe_pos:X}_pkg{idx}_type{pkg_type}.bin'
            with open(f'/workspace/{pkg_name}', 'wb') as f:
                f.write(pkg_data)
            print(f"  Extracted {pkg_name}")

