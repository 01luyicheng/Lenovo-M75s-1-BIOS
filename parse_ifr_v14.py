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

# GuidDefinedSection 8 contains an FV header starting at offset 0x20
# This means the data is likely a raw firmware volume image
# Let's extract it and parse it

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

# Find the section with FV header
fv_section = None
for gs in all_guid_sections:
    if b'_FVH' in gs['data']:
        fv_section = gs
        break

if fv_section is None:
    print("No section with FV header found")
    sys.exit(1)

print(f"Found section with FV header, size={len(fv_section['data'])}")

# The section data starts with a header, then the actual content
# For GuidDefinedSection with LZMA:
# - Section header (common section header + GUID + attributes + data offset)
# - Compressed data
# But looking at the hex dump, the FV header is at offset 0x20 within the section data
# This suggests the section might already be decompressed or has a different structure

# Let's find the exact offset of _FVH
fv_offset_in_section = fv_section['data'].find(b'_FVH')
print(f"_FVH at offset 0x{fv_offset_in_section:X} in section data")

# Extract the FV data starting from the _FVH position minus the ZeroVector (16 bytes) + GUID (16 bytes) = 32 bytes before _FVH
# Actually, _FVH is at offset 40 in the FV header, so the FV starts 40 bytes before _FVH
fv_start = fv_offset_in_section - 40
if fv_start < 0:
    fv_start = 0

fv_data = fv_section['data'][fv_start:]
print(f"Extracted FV data, size={len(fv_data)}")

# Save for analysis
with open('/workspace/extracted_fv.bin', 'wb') as f:
    f.write(fv_data)

# Now let's parse this FV using uefi_firmware
fv_parser = uefi_firmware.AutoParser(fv_data)
parsed_fv = fv_parser.parse()

if parsed_fv is None:
    print("Failed to parse extracted FV")
    sys.exit(1)

print(f"Parsed FV type: {type(parsed_fv).__name__}")

# Collect all objects from this FV
fv_objects = []
def collect_fv_objects(obj, depth=0):
    if hasattr(obj, 'data') and obj.data and len(obj.data) > 100:
        obj_type = type(obj).__name__
        name = getattr(obj, 'name', '') or ''
        if isinstance(name, bytes):
            name = name.decode('utf-8', errors='ignore')
        elif not isinstance(name, str):
            name = str(name)
        
        fv_objects.append({
            'type': obj_type,
            'name': name,
            'size': len(obj.data),
            'data': obj.data,
            'depth': depth
        })
    
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            collect_fv_objects(child, depth + 1)

collect_fv_objects(parsed_fv)
print(f"Found {len(fv_objects)} objects in extracted FV")

# Search for target strings
print("\nSearching for target strings in extracted FV:")
targets = [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']
for obj in fv_objects:
    found = []
    for target in targets:
        if target in obj['data']:
            found.append(target.decode('latin-1'))
    if found:
        print(f"  {obj['type']}/{obj['name']}: size={obj['size']}, targets={found}")

