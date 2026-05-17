import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# We found NVAR (NVRAM Variable) structures at 0x37090 and 0x1037090
# These contain Setup variable data
# Let's analyze the NVAR structure

# NVAR format (from EDK2):
# Signature "NVAR" (4 bytes)
# Size (2 bytes)
# Next (4 bytes) - offset to next NVAR or 0xFFFFFF7F if last
# Attributes (2 bytes)
# NameSize (1 byte) - if bit 7 is set, it's a GUIDed name
# DataSize (3 bytes)
# Then name and data

def parse_nvar(data, offset):
    if offset + 12 > len(data):
        return None
    
    sig = data[offset:offset+4]
    if sig != b'NVAR':
        return None
    
    size = struct.unpack('<H', data[offset+4:offset+6])[0]
    next_offset = struct.unpack('<I', data[offset+6:offset+10])[0]
    attributes = struct.unpack('<H', data[offset+10:offset+12])[0]
    
    # NameSize/DataSize encoding
    name_data_size = data[offset+12]
    name_size = name_data_size & 0x7F
    is_guided = (name_data_size & 0x80) != 0
    
    # Data size is 3 bytes (but encoded differently)
    data_size = data[offset+13] | (data[offset+14] << 8) | (data[offset+15] << 16)
    
    result = {
        'offset': offset,
        'size': size,
        'next_offset': next_offset,
        'attributes': attributes,
        'name_size': name_size,
        'data_size': data_size,
        'is_guided': is_guided
    }
    
    # Parse name
    name_start = offset + 16
    if is_guided:
        # GUID (16 bytes) + ASCII name
        guid = data[name_start:name_start+16]
        name_end = name_start + 16
        while name_end < offset + size and data[name_end] != 0:
            name_end += 1
        name = data[name_start+16:name_end].decode('ascii', errors='ignore')
        result['guid'] = guid.hex()
        result['name'] = name
    else:
        name_end = name_start
        while name_end < offset + size and data[name_end] != 0:
            name_end += 1
        name = data[name_start:name_end].decode('ascii', errors='ignore')
        result['name'] = name
    
    return result

# Parse NVARs at 0x37090
print("=== NVARs at 0x37090 ===")
offset = 0x37090
nvar_count = 0
while offset < len(data) - 12:
    nvar = parse_nvar(data, offset)
    if nvar is None:
        break
    nvar_count += 1
    print(f"NVAR {nvar_count}: offset=0x{nvar['offset']:X}, size={nvar['size']}, name='{nvar['name']}', data_size={nvar['data_size']}")
    if nvar['name'] == 'Setup':
        print(f"  -> Found Setup variable!")
        # Extract Setup data
        setup_data_offset = offset + 16 + nvar['name_size'] + (16 if nvar['is_guided'] else 0)
        setup_data = data[setup_data_offset:setup_data_offset + nvar['data_size']]
        print(f"  Setup data size: {len(setup_data)} bytes")
        print(f"  Setup data first 64 bytes: {setup_data[:64].hex()}")
    
    # Move to next NVAR
    if nvar['next_offset'] == 0xFFFFFF7F:
        break
    if nvar['next_offset'] == 0:
        offset += nvar['size']
    else:
        offset = nvar['next_offset']
    
    if nvar_count > 50:
        break

# Also check at 0x1037090 (duplicate)
print("\n=== NVARs at 0x1037090 ===")
offset = 0x1037090
nvar_count = 0
while offset < len(data) - 12:
    nvar = parse_nvar(data, offset)
    if nvar is None:
        break
    nvar_count += 1
    print(f"NVAR {nvar_count}: offset=0x{nvar['offset']:X}, size={nvar['size']}, name='{nvar['name']}', data_size={nvar['data_size']}")
    if nvar['name'] == 'Setup':
        print(f"  -> Found Setup variable!")
        setup_data_offset = offset + 16 + nvar['name_size'] + (16 if nvar['is_guided'] else 0)
        setup_data = data[setup_data_offset:setup_data_offset + nvar['data_size']]
        print(f"  Setup data size: {len(setup_data)} bytes")
        print(f"  Setup data first 64 bytes: {setup_data[:64].hex()}")
    
    if nvar['next_offset'] == 0xFFFFFF7F:
        break
    if nvar['next_offset'] == 0:
        offset += nvar['size']
    else:
        offset = nvar['next_offset']
    
    if nvar_count > 50:
        break

