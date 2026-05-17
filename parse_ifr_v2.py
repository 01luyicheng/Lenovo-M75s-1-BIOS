import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# Let's take a different approach - search for the actual Setup module
# which contains the IFR data. In AMI/Insyde/Phoenix BIOS, Setup data
# is often in a compressed section. Let's search for known patterns.

# Search for "Setup" as UTF-16LE string (common in HII)
setup_utf16 = b'S\x00e\x00t\x00u\x00p\x00'
setup_positions = []
idx = 0
while True:
    idx = data.find(setup_utf16, idx)
    if idx == -1:
        break
    setup_positions.append(idx)
    idx += 1

print(f"Found 'Setup' (UTF-16LE) at {len(setup_positions)} positions")
for pos in setup_positions[:20]:
    print(f"  0x{pos:X}")

# Search for HII package signatures more carefully
# EFI_HII_PACKAGE_FORM = 0x02
# The package header is: Length(3 bytes, little-endian) + Type(1 byte)
# But in raw ROM, these might not be aligned

# Alternative: Search for FORM_SET opcode pattern
# FORM_SET = 0x01, followed by length (2 bytes), scope=1, then GUID
form_set_positions = []
i = 0
while i < len(data) - 24:
    if data[i] == 0x01:
        length = data[i+1] | (data[i+2] << 8)
        scope = data[i+3]
        # GUID should have certain pattern (not all zeros, not all FF)
        guid = data[i+4:i+20]
        if length >= 21 and length < 0x200 and scope == 0x01 and guid != bytes(16) and guid != b'\xff'*16:
            # Additional check: GUID should look reasonable
            # Check if any of the known setup GUIDs match
            form_set_positions.append((i, length))
    i += 1

print(f"\nFound {len(form_set_positions)} potential FORM_SET opcodes")
for pos, length in form_set_positions[:20]:
    guid = data[pos+4:pos+20]
    print(f"  0x{pos:X}: len={length}, GUID={guid.hex()}")

# Let's look at the context around the first few
print("\n\nAnalyzing first FORM_SET context:")
if form_set_positions:
    pos, length = form_set_positions[0]
    start = max(0, pos - 64)
    end = min(len(data), pos + 256)
    context = data[start:end]
    print(f"Context hex (0x{start:X} - 0x{end:X}):")
    for j in range(0, len(context), 16):
        hex_part = ' '.join(f'{b:02X}' for b in context[j:j+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context[j:j+16])
        print(f"  0x{start+j:06X}: {hex_part:<48} {ascii_part}")

