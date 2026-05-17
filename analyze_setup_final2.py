import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The PE32 search only found 6 images, which is very few for a 32MB ROM.
# This suggests the ROM has a different structure.
# Let's look at the actual structure more carefully.

# The ROM starts with 0x28 bytes of padding, then an FV header at 0x28
# Let's parse the FV properly

# EFI_FIRMWARE_VOLUME_HEADER
# ZeroVector: 16 bytes
# FileSystemGuid: 16 bytes  
# FvLength: 8 bytes
# Signature: 4 bytes '_FVH'
# Attributes: 4 bytes
# HeaderLength: 2 bytes
# Checksum: 2 bytes
# ExtHeaderOffset: 2 bytes
# Reserved: 1 byte
# Revision: 1 byte

fv_offset = 0x28
print(f"FV at 0x{fv_offset:X}:")
print(f"  ZeroVector: {data[fv_offset:fv_offset+16].hex()}")
print(f"  FileSystemGuid: {data[fv_offset+16:fv_offset+32].hex()}")
fv_length = struct.unpack('<Q', data[fv_offset+32:fv_offset+40])[0]
print(f"  FvLength: 0x{fv_length:X}")
print(f"  Signature: {data[fv_offset+40:fv_offset+44]}")
attributes = struct.unpack('<I', data[fv_offset+44:fv_offset+48])[0]
print(f"  Attributes: 0x{attributes:08X}")
header_length = struct.unpack('<H', data[fv_offset+48:fv_offset+50])[0]
print(f"  HeaderLength: 0x{header_length:X}")

# The FV length is 0x20000, which is very small.
# Let's search for more FVs
print("\nSearching for all FVs:")
fvs = []
idx = 0
while idx < len(data) - 44:
    if data[idx:idx+4] == b'_FVH':
        # Go back to find the start
        start = idx - 40
        if start < 0:
            start = 0
        fv_length = struct.unpack('<Q', data[start+32:start+40])[0]
        header_length = struct.unpack('<H', data[start+48:start+50])[0]
        if fv_length > 0 and fv_length < len(data) - start:
            fvs.append((start, fv_length, header_length))
            idx = start + fv_length
            continue
    idx += 1

print(f"Found {len(fvs)} FVs:")
for fv in fvs:
    print(f"  0x{fv[0]:X}: length=0x{fv[1]:X}, header=0x{fv[2]:X}")

# The ROM seems to have multiple FVs. Let's look at the large ones.
# The second FV at 0xD00E50 has a huge length which seems wrong.
# Let's look at offset 0xD00000 region

print("\n\nAnalyzing region around 0xD00000:")
for i in range(0xD00000, 0xD00080, 16):
    hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# Let's look for the actual BIOS region
# In Intel flash descriptors, the BIOS region usually starts after the descriptor
# But this might be an AMD system

# Search for common AMD BIOS signatures
amd_signatures = {
    b'AGESA': 'AMD AGESA',
    b'APCB': 'AMD APCB',
    b'APOB': 'AMD APOB',
    b'PSP': 'AMD PSP',
    b'SMU': 'AMD SMU',
}

print("\nSearching for AMD signatures:")
for sig, desc in amd_signatures.items():
    count = data.count(sig)
    if count > 0:
        print(f"  {desc} ({sig}): {count} occurrences")

# Let's look at the structure at 0xD00E50
# From earlier, we saw _FVH at 0xD00028
print("\n\nFV at 0xD00028:")
fv2_offset = 0xD00028
print(f"  ZeroVector: {data[fv2_offset:fv2_offset+16].hex()}")
print(f"  FileSystemGuid: {data[fv2_offset+16:fv2_offset+32].hex()}")
fv2_length = struct.unpack('<Q', data[fv2_offset+32:fv2_offset+40])[0]
print(f"  FvLength: 0x{fv2_length:X}")
print(f"  Signature: {data[fv2_offset+40:fv2_offset+44]}")

# This FV length is also small. The large data must be somewhere else.
# Let's search for PE32 images more broadly
print("\n\nSearching for all MZ headers:")
mz_positions = []
idx = 0
while True:
    idx = data.find(b'MZ', idx)
    if idx == -1:
        break
    mz_positions.append(idx)
    idx += 1

print(f"Found {len(mz_positions)} MZ headers")

# Validate PE signatures
pe_positions = []
for mz_pos in mz_positions:
    if mz_pos + 0x3C + 4 <= len(data):
        pe_offset = struct.unpack('<I', data[mz_pos+0x3C:mz_pos+0x3C+4])[0]
        if mz_pos + pe_offset + 4 <= len(data):
            if data[mz_pos+pe_offset:mz_pos+pe_offset+4] == b'PE\x00\x00':
                pe_positions.append(mz_pos)

print(f"Found {len(pe_positions)} valid PE images")
for pe_pos in pe_positions[:20]:
    print(f"  0x{pe_pos:X}")

