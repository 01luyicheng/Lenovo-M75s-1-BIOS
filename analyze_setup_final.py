import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The strings we found are debug/log strings in PEIM/DXE drivers, not IFR form strings.
# This is an AMD-based system (references to SMU, GNB, APOB, etc.).
# The Setup IFR data might be in a different format or compressed differently.

# Let's try to use the uefi_firmware library more effectively.
# The library might be able to extract IFR if we use the right approach.

sys.path.insert(0, '/root/.pyenv/versions/3.14.4/lib/python3.14/site-packages')
import uefi_firmware

# Let's look for objects that might contain the actual Setup menu IFR
# The Setup menu is typically in a DXE driver or SMM module

# Search for known Setup-related GUIDs in the raw ROM
# AMI Setup GUID: E20B9263-9560-4D93-9D19-FA720C13A21E
ami_setup_guid = bytes([0x63, 0x92, 0x0B, 0xE2, 0x60, 0x95, 0x93, 0x4D, 0x9D, 0x19, 0xFA, 0x72, 0x0C, 0x13, 0xA2, 0x1E])

# Search for this GUID
idx = data.find(ami_setup_guid)
print(f"AMI Setup GUID found: {idx != -1}")
if idx != -1:
    print(f"  at offset 0x{idx:X}")

# Let's search for the Setup module by looking for the string "Setup" near PE32 headers
# and checking if the module contains HII data

# First, let's find all PE32 images in the ROM
pe32_positions = []
idx = 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    # Validate: check for PE signature at offset from MZ header
    if idx + 0x3C + 4 <= len(data):
        pe_offset = struct.unpack('<I', data[idx+0x3C:idx+0x3C+4])[0]
        if idx + pe_offset + 4 <= len(data) and data[idx+pe_offset:idx+pe_offset+4] == b'PE\x00\x00':
            pe32_positions.append(idx)
    idx += 1

print(f"\nFound {len(pe32_positions)} valid PE32 images")

# For each PE32, check if it contains our target strings AND HII package signatures
setup_pe32s = []
targets = [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']

for pe_pos in pe32_positions:
    # Get PE size (from optional header)
    pe_offset = struct.unpack('<I', data[pe_pos+0x3C:pe_pos+0x3C+4])[0]
    if pe_pos + pe_offset + 24 > len(data):
        continue
    
    # Get size from optional header
    oh_offset = pe_pos + pe_offset + 24
    if oh_offset + 4 > len(data):
        continue
    
    # For PE32+ (64-bit), the optional header starts at offset 24 from PE signature
    # SizeOfImage is at offset 0x38 from optional header start
    # But we need to know if it's PE32 or PE32+
    magic = struct.unpack('<H', data[oh_offset:oh_offset+2])[0]
    if magic == 0x10b:  # PE32
        size_of_image_offset = oh_offset + 0x38
    elif magic == 0x20b:  # PE32+
        size_of_image_offset = oh_offset + 0x44
    else:
        continue
    
    if size_of_image_offset + 4 > len(data):
        continue
    
    size_of_image = struct.unpack('<I', data[size_of_image_offset:size_of_image_offset+4])[0]
    pe_end = pe_pos + size_of_image
    
    if pe_end > len(data):
        continue
    
    pe_data = data[pe_pos:pe_end]
    
    # Check for target strings
    found_targets = []
    for target in targets:
        if target in pe_data:
            found_targets.append(target.decode('latin-1'))
    
    if found_targets:
        # Check for HII packages
        has_hii = False
        i = 0
        while i < len(pe_data) - 4:
            length = pe_data[i] | (pe_data[i+1] << 8) | (pe_data[i+2] << 16)
            pkg_type = pe_data[i+3]
            if pkg_type in [0x02, 0x04] and length >= 0x10 and length <= len(pe_data) - i:
                if pkg_type == 0x02 and i + 4 < len(pe_data) and pe_data[i+4] == 0x01:
                    has_hii = True
                    break
                elif pkg_type == 0x04:
                    has_hii = True
                    break
            i += 1
        
        setup_pe32s.append({
            'offset': pe_pos,
            'size': len(pe_data),
            'targets': found_targets,
            'has_hii': has_hii
        })

print(f"\nFound {len(setup_pe32s)} PE32 images with target strings")
for pe in sorted(setup_pe32s, key=lambda x: x['size'], reverse=True)[:20]:
    print(f"  0x{pe['offset']:X}: size=0x{pe['size']:X}, has_hii={pe['has_hii']}, targets={pe['targets']}")

# Let's save the largest PE32 with HII data for further analysis
hii_pe32s = [pe for pe in setup_pe32s if pe['has_hii']]
if hii_pe32s:
    largest_hii = sorted(hii_pe32s, key=lambda x: x['size'], reverse=True)[0]
    print(f"\nLargest PE32 with HII: 0x{largest_hii['offset']:X}, size=0x{largest_hii['size']:X}")
    
    pe_data = data[largest_hii['offset']:largest_hii['offset']+largest_hii['size']]
    with open('/workspace/largest_setup_pe32.bin', 'wb') as f:
        f.write(pe_data)
    print("Saved to /workspace/largest_setup_pe32.bin")
    
    # Extract HII packages
    print("\nExtracting HII packages from largest PE32:")
    i = 0
    pkg_count = 0
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
                pkg_count += 1
                pkg_data = pe_data[i:i+length]
                pkg_name = f"hii_pkg_{pkg_count}_type{pkg_type}_0x{i:X}.bin"
                with open(f'/workspace/{pkg_name}', 'wb') as f:
                    f.write(pkg_data)
                print(f"  Saved {pkg_name}: offset=0x{i:X}, length=0x{length:X}, type={pkg_type}")
                i += length
                continue
        i += 1

