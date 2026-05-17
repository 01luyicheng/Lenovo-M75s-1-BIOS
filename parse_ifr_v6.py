import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The string package at 0x25903 doesn't look like a valid UEFI HII string package.
# The header starts with 0xFF which is suspicious.
# Let's reconsider - this ROM might be using a different format.

# Let's look at the actual file structure more carefully.
# This could be an AMI Aptio BIOS with specific section formats.

# AMI BIOS often uses the following structure:
# - Firmware Volume Header
# - Files with specific GUIDs
# - Each file has sections

# Let's search for the Firmware Volume signature "_FVH"
fvh_positions = []
idx = 0
while True:
    idx = data.find(b'_FVH', idx)
    if idx == -1:
        break
    fvh_positions.append(idx)
    idx += 1

print(f"Found '_FVH' at {len(fvh_positions)} positions")
for pos in fvh_positions[:10]:
    print(f"  0x{pos:X}")

# Let's also search for the Intel flash descriptor signature
if data[:4] == b'\x5a\xa5\xf0\x0f' or data[:4] == b'\xff\xff\xff\xff':
    print("\nROM starts with potential flash descriptor pattern")

# Search for common BIOS signatures
signatures = {
    b'IFWI': 'Intel Firmware',
    b'$FPT': 'Flash Partition Table',
    b'BIOS': 'BIOS region',
    b'ROM ': 'ROM signature',
    b'OROM': 'Option ROM',
    b'PCIR': 'PCI ROM',
    b'VETO': 'Veto signature',
    b'_AM_': 'AMI signature',
    b'_ASUS_': 'ASUS signature',
}

print("\nSearching for common BIOS signatures:")
for sig, desc in signatures.items():
    idx = data.find(sig)
    if idx != -1:
        print(f"  {desc} ({sig}): 0x{idx:X}")

# Let's examine the first few KB of the ROM
print("\nFirst 256 bytes of ROM:")
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# Search for the Setup-related module more carefully
# In AMI BIOS, Setup data is often in a module with name containing "Setup"
# Let's search for ASCII strings related to Setup
print("\n\nSearching for Setup-related ASCII strings:")
setup_strings = []
for m in re.finditer(b'Setup[\w]*', data):
    pos = m.start()
    s = m.group().decode('ascii', errors='ignore')
    setup_strings.append((pos, s))

for pos, s in setup_strings[:30]:
    print(f"  0x{pos:X}: {s}")

