import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The NVAR parsing is not working correctly. Let's look at the raw bytes more carefully.
# From the hex dump earlier:
# 0x037082: ...4E 56 41 52 7F 07 FF FF FF 83 00 53 74 64 44 65 66 61  ........NVAR.......StdDefa
# 0x0370A2: 75 6C 74 73 00 4E 56 41 52 1E 02 FF FF FF 83 00 53 65 74 75  ults.NVAR......Setup

# So NVAR starts at 0x37088 (the 'N' of 'NVAR')
# Let's manually parse

offset = 0x37088
nvar_data = data[offset:offset+32]
print(f"NVAR at 0x{offset:X}: {nvar_data.hex()}")
print(f"  Signature: {nvar_data[0:4]}")
print(f"  Size: {struct.unpack('<H', nvar_data[4:6])[0]}")
print(f"  Next: {struct.unpack('<I', nvar_data[6:10])[0]:08X}")
print(f"  Attr: {struct.unpack('<H', nvar_data[10:12])[0]:04X}")
print(f"  NameSize/DataSize byte: {nvar_data[12]:02X}")
print(f"  Following bytes: {nvar_data[13:20].hex()}")

# Let's look at the context more carefully
print("\nContext around 0x37088:")
start = 0x37080
end = min(len(data), 0x37180)
for i in range(start, end, 16):
    hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# Let's search for all NVAR structures more carefully
print("\n\nSearching for all NVAR structures:")
nvar_list = []
idx = 0
while True:
    idx = data.find(b'NVAR', idx)
    if idx == -1:
        break
    if idx + 12 <= len(data):
        size = struct.unpack('<H', data[idx+4:idx+6])[0]
        next_off = struct.unpack('<I', data[idx+6:idx+10])[0]
        attr = struct.unpack('<H', data[idx+10:idx+12])[0]
        if size > 12 and size < 0x10000:
            nvar_list.append((idx, size, next_off, attr))
    idx += 1

print(f"Found {len(nvar_list)} NVAR structures")
for nvar in nvar_list[:30]:
    idx, size, next_off, attr = nvar
    # Try to find name
    name_start = idx + 16
    name_end = name_start
    while name_end < idx + size and data[name_end] != 0:
        name_end += 1
    name = data[name_start:name_end].decode('ascii', errors='ignore') if name_end > name_start else ''
    print(f"  0x{idx:X}: size={size}, next=0x{next_off:08X}, attr=0x{attr:04X}, name='{name}'")

