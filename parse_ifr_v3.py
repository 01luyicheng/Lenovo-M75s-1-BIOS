import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The ROM seems to have IFR data but the parsing approach needs refinement.
# Let's search for actual UEFI HII Form package signatures more carefully.
# In UEFI, HII packages are stored in firmware volumes or as PE/COFF sections.

# Let's search for the specific byte pattern that indicates a form package:
# The package starts with 3-byte length + 1-byte type (0x02)
# Then immediately: 0x01 (FORM_SET opcode) + 2-byte length + 0x01 (scope)

# But first, let's look at the "Setup" string positions more carefully
# and see if there's IFR data nearby

setup_positions = []
idx = 0
while True:
    idx = data.find(b'S\x00e\x00t\x00u\x00p\x00', idx)
    if idx == -1:
        break
    setup_positions.append(idx)
    idx += 2

print(f"Found 'Setup' (UTF-16LE) at {len(setup_positions)} positions")

# For each Setup position, look for nearby IFR patterns
for pos in setup_positions[:10]:
    print(f"\n--- Position 0x{pos:X} ---")
    # Look backward for form package header or FORM_SET
    for back in range(0, 512, 2):
        check_pos = pos - back
        if check_pos < 0:
            break
        # Check for FORM_SET opcode
        if data[check_pos] == 0x01 and check_pos + 3 < len(data):
            length = data[check_pos+1] | (data[check_pos+2] << 8)
            scope = data[check_pos+3]
            if length >= 21 and length < 0x200 and scope == 0x01:
                print(f"  FORM_SET at 0x{check_pos:X}, len={length}")
                guid = data[check_pos+4:check_pos+20]
                print(f"  GUID: {guid.hex()}")
                break
        # Check for HII package header (type 0x02)
        if check_pos + 3 < len(data):
            length = data[check_pos] | (data[check_pos+1] << 8) | (data[check_pos+2] << 16)
            pkg_type = data[check_pos+3]
            if pkg_type == 0x02 and length > 4 and length < 0x100000:
                print(f"  HII Form Package header at 0x{check_pos:X}, len={length}")
                break

# Let's try a broader search - look for the specific pattern of HII form packages
# that contain our target strings
print("\n\n=== Searching for HII Form Packages near target strings ===")

targets = {
    b'Above 4G Decoding': 'Above 4G Decoding',
    b'Above4G': 'Above4G',
    b'IOMMU': 'IOMMU',
    b'SVM Mode': 'SVM Mode',
    b'SMT Mode': 'SMT Mode',
    b'Downcore': 'Downcore',
    b'DownCore': 'DownCore',
    b'Down Core': 'Down Core',
    b'ASPM': 'ASPM',
    b'PCIe Link Speed': 'PCIe Link Speed',
    b'Memory Clock': 'Memory Clock',
    b'MemClk': 'MemClk',
    b'Power Down Mode': 'Power Down Mode',
    b'PowerDown': 'PowerDown',
}

for pattern, name in targets.items():
    idx = data.find(pattern)
    if idx != -1:
        print(f"\n{name} at 0x{idx:X}")
        # Search backward for HII package header
        found_pkg = False
        for back in range(0, 4096):
            check_pos = idx - back
            if check_pos < 0:
                break
            if check_pos + 3 < len(data):
                length = data[check_pos] | (data[check_pos+1] << 8) | (data[check_pos+2] << 16)
                pkg_type = data[check_pos+3]
                if pkg_type == 0x02 and length > 0x10 and length < 0x200000:
                    # Verify it starts with FORM_SET
                    if check_pos + 4 < len(data) and data[check_pos+4] == 0x01:
                        print(f"  HII Form Package at 0x{check_pos:X}, length=0x{length:X}")
                        found_pkg = True
                        break
        if not found_pkg:
            print(f"  No HII Form Package found nearby")

