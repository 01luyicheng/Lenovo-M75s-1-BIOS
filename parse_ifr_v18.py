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

# Find the GuidDefinedSection with FV header
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

fv_section = None
for gs in all_guid_sections:
    if b'_FVH' in gs['data'] and len(gs['data']) > 1000000:
        fv_section = gs
        break

fv_offset_in_section = fv_section['data'].find(b'_FVH')
fv_start = fv_offset_in_section - 40
if fv_start < 0:
    fv_start = 0
fv_data = fv_section['data'][fv_start:]

fv_parser = uefi_firmware.AutoParser(fv_data)
parsed_fv = fv_parser.parse()

# The HII packages we found don't seem to contain valid string data.
# Let's try a completely different approach.
# In AMI BIOS, Setup settings are often stored in NVAR (NVRAM Variable) format
# or in specific Setup modules that use a different structure than standard UEFI HII.

# Let's search for NVAR signatures
nvar_positions = []
idx = 0
while True:
    idx = data.find(b'NVAR', idx)
    if idx == -1:
        break
    nvar_positions.append(idx)
    idx += 1

print(f"Found 'NVAR' at {len(nvar_positions)} positions")
for pos in nvar_positions[:20]:
    print(f"  0x{pos:X}")

# Let's also search for the Setup variable directly
setup_var_positions = []
idx = 0
while True:
    idx = data.find(b'Setup\x00', idx)
    if idx == -1:
        break
    setup_var_positions.append(idx)
    idx += 1

print(f"\nFound 'Setup\\x00' at {len(setup_var_positions)} positions")
for pos in setup_var_positions[:20]:
    print(f"  0x{pos:X}")

# Let's look at the context around the first Setup variable
if setup_var_positions:
    pos = setup_var_positions[0]
    start = max(0, pos - 64)
    end = min(len(data), pos + 128)
    print(f"\nContext around first 'Setup\\x00' at 0x{pos:X}:")
    for i in range(start, end, 16):
        hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
        print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# Let's search for the actual IFR opcodes in the raw ROM data
# The issue might be that the IFR data is not in HII packages but directly embedded
# Let's search for FORM_SET opcode (0x01) followed by a valid GUID

print("\n\nSearching for FORM_SET opcodes with valid GUIDs...")
form_set_positions = []
i = 0
while i < len(data) - 24:
    if data[i] == 0x01:
        length = data[i+1] | (data[i+2] << 8)
        scope = data[i+3]
        guid = data[i+4:i+20]
        # Check if GUID looks valid (not all zeros, not all FF, has some variety)
        if length >= 21 and length < 0x200 and scope == 0x01:
            unique_bytes = len(set(guid))
            if unique_bytes > 2 and guid != bytes(16) and guid != b'\xff'*16:
                # Check if it's followed by a string ID (2 bytes, usually small)
                if i + 22 <= len(data):
                    string_id = data[i+20] | (data[i+21] << 8)
                    if string_id < 0x1000:  # Reasonable string ID
                        form_set_positions.append((i, length, guid.hex()))
    i += 1

print(f"Found {len(form_set_positions)} valid FORM_SET opcodes")
for pos, length, guid in form_set_positions[:20]:
    print(f"  0x{pos:X}: len={length}, GUID={guid}")

