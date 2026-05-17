import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# This looks like an AMI Aptio BIOS with firmware volumes.
# The first FV is at offset 0x28 (after the first 0x28 bytes of padding/flash descriptor).
# Let's parse the firmware volumes properly.

# EFI_FIRMWARE_VOLUME_HEADER format:
# ZeroVector (16 bytes)
# FileSystemGuid (16 bytes)
# FvLength (8 bytes)
# Signature (4 bytes) = '_FVH'
# Attributes (4 bytes)
# HeaderLength (2 bytes)
# Checksum (2 bytes)
# ExtHeaderOffset (2 bytes)
# Reserved (1 byte)
# Revision (1 byte)

def parse_fv_header(data, offset):
    if offset + 48 > len(data):
        return None
    
    zero_vector = data[offset:offset+16]
    fs_guid = data[offset+16:offset+32]
    fv_length = struct.unpack('<Q', data[offset+32:offset+40])[0]
    signature = data[offset+40:offset+44]
    attributes = struct.unpack('<I', data[offset+44:offset+48])[0]
    header_length = struct.unpack('<H', data[offset+48:offset+50])[0]
    
    if signature != b'_FVH':
        return None
    
    return {
        'offset': offset,
        'fs_guid': fs_guid.hex(),
        'fv_length': fv_length,
        'attributes': attributes,
        'header_length': header_length
    }

# Parse all firmware volumes
fv_list = []
idx = 0
while idx < len(data) - 48:
    fv = parse_fv_header(data, idx)
    if fv:
        fv_list.append(fv)
        idx += fv['fv_length']
        # Align to 8 bytes
        idx = (idx + 7) & ~7
    else:
        idx += 0x28  # Search every 0x28 bytes

print(f"Found {len(fv_list)} Firmware Volumes:")
for fv in fv_list:
    print(f"  Offset 0x{fv['offset']:X}: length=0x{fv['fv_length']:X}, hdr=0x{fv['header_length']:X}, GUID={fv['fs_guid']}")

# Now let's look inside the firmware volumes for files
# EFI_FFS_FILE_HEADER format (after FV header):
# Name (16 bytes GUID)
# IntegrityCheck (2 bytes)
# Type (1 byte)
# Attributes (1 byte)
# Size (3 bytes)
# State (1 byte)

FFS_FILE_TYPES = {
    0x01: 'RAW',
    0x02: 'FREEFORM',
    0x03: 'SECURITY_CORE',
    0x04: 'PEI_CORE',
    0x05: 'DXE_CORE',
    0x06: 'PEIM',
    0x07: 'DRIVER',
    0x08: 'COMBINED_PEIM_DRIVER',
    0x09: 'APPLICATION',
    0x0A: 'SMM',
    0x0B: 'FIRMWARE_VOLUME_IMAGE',
    0x0C: 'COMBINED_SMM_DXE',
    0x0D: 'SMM_CORE',
    0x0E: 'SMM_STANDALONE',
    0x0F: 'SMM_CORE_STANDALONE',
    0xF0: 'FFS_PAD',
}

def parse_ffs_files(data, fv_offset, fv_length, fv_header_length):
    files = []
    pos = fv_offset + fv_header_length
    end = fv_offset + fv_length
    
    # Align to 8 bytes
    pos = (pos + 7) & ~7
    
    while pos + 24 <= end:
        name = data[pos:pos+16]
        integrity_check = struct.unpack('<H', data[pos+16:pos+18])[0]
        ftype = data[pos+18]
        attributes = data[pos+19]
        size = data[pos+20] | (data[pos+21] << 8) | (data[pos+22] << 16)
        state = data[pos+23]
        
        # Validate
        if size == 0 or size > fv_length or pos + size > end:
            pos += 8
            continue
        
        # Check if it looks like a valid file
        if ftype in FFS_FILE_TYPES and size >= 24:
            files.append({
                'offset': pos,
                'guid': name.hex(),
                'type': FFS_FILE_TYPES.get(ftype, f'0x{ftype:02X}'),
                'type_raw': ftype,
                'size': size,
                'attributes': attributes
            })
            pos += size
            # Align to 8 bytes
            pos = (pos + 7) & ~7
        else:
            pos += 8
    
    return files

# Parse files in each FV
all_files = []
for fv in fv_list:
    files = parse_ffs_files(data, fv['offset'], fv['fv_length'], fv['header_length'])
    all_files.extend(files)
    print(f"\nFV at 0x{fv['offset']:X}: {len(files)} files")
    for f in files[:10]:
        print(f"  0x{f['offset']:X}: {f['type']} (0x{f['type_raw']:02X}), size=0x{f['size']:X}, GUID={f['guid']}")

# Search for Setup-related files
print("\n\nSearching for Setup-related files:")
setup_files = []
for f in all_files:
    # Check file data for "Setup" strings
    fdata = data[f['offset']:f['offset']+f['size']]
    if b'Setup' in fdata or b'setup' in fdata:
        setup_files.append(f)
        print(f"  0x{f['offset']:X}: {f['type']}, size=0x{f['size']:X}, GUID={f['guid']}")

