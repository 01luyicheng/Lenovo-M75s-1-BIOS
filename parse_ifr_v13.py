import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

sys.path.insert(0, '/root/.pyenv/versions/3.14.4/lib/python3.14/site-packages')
import uefi_firmware

parser = uefi_firmware.AutoParser(data)
firmware = parser.parse()

# The section is LZMA compressed but the library might not have decompressed it properly
# Let's look at the structure more carefully.

# GuidDefinedSection header:
# EFI_COMMON_SECTION_HEADER (3 bytes size + 1 byte type = 0x14 for GUID-defined)
# SectionDefinitionGuid (16 bytes)
# DataOffset (2 bytes) - offset to actual data from start of section header
# Attributes (2 bytes)
# Then the actual data (possibly compressed)

# Let's find all GuidDefinedSection objects and check their structure
all_guid_sections = []

def collect_guid_sections(obj, depth=0):
    obj_type = type(obj).__name__
    if obj_type == 'GuidDefinedSection' and hasattr(obj, 'data') and obj.data:
        guid = getattr(obj, 'guid', b'')
        if isinstance(guid, bytes):
            guid_hex = guid.hex()
        else:
            guid_hex = str(guid)
        all_guid_sections.append({
            'guid': guid_hex,
            'size': len(obj.data),
            'data': obj.data,
            'obj': obj
        })
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            collect_guid_sections(child, depth + 1)

collect_guid_sections(firmware)
print(f"Found {len(all_guid_sections)} GuidDefinedSection objects")

for gs in all_guid_sections:
    print(f"  GUID: {gs['guid']}, size: {gs['size']}")

# Let's look at the first bytes of each to understand the structure
for i, gs in enumerate(all_guid_sections):
    print(f"\nGuidDefinedSection {i}:")
    d = gs['data'][:64]
    for j in range(0, 64, 16):
        hex_part = ' '.join(f'{b:02X}' for b in d[j:j+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in d[j:j+16])
        print(f"  0x{j:06X}: {hex_part:<48} {ascii_part}")

# The uefi_firmware library should handle LZMA decompression automatically.
# But it seems like the data is still compressed or the parsing is incomplete.
# Let's try to use the library's process() method or look at children.

print("\n\nChecking if GuidDefinedSection has child objects...")
for i, gs in enumerate(all_guid_sections):
    obj = gs['obj']
    if hasattr(obj, 'objects') and obj.objects:
        print(f"GuidDefinedSection {i} has {len(obj.objects)} children:")
        for child in obj.objects:
            print(f"  {type(child).__name__}: size={len(child.data) if hasattr(child, 'data') and child.data else 0}")
    else:
        print(f"GuidDefinedSection {i} has no children")

