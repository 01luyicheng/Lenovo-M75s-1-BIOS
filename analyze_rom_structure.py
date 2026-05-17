import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The PE32 at 0x6D78F4 is actually a small PE (0x7A00 bytes) followed by other data.
# The file was extracted incorrectly because we used size_of_image which is corrupted.
# Let's understand the actual ROM structure.

# From earlier analysis, we found FVs at:
# 0x0: length=0x20000
# 0x37000: length=0x20000
# 0x77000: length=0x20000
# 0x6CF000: length=0x631000
# 0xD00000: length=0x300000
# 0x1000000: length=0x20000
# 0x1037000: length=0x20000
# 0x1077000: length=0x20000
# 0x1411000: length=0x8EF000

# Let's look at the FV at 0x6CF000 which is quite large
fv_offset = 0x6CF000
print(f"\nFV at 0x{fv_offset:X}:")
print(f"  First 64 bytes: {data[fv_offset:fv_offset+64].hex()}")

# Parse FV header
zero_vector = data[fv_offset:fv_offset+16]
fs_guid = data[fv_offset+16:fv_offset+32]
fv_length = struct.unpack('<Q', data[fv_offset+32:fv_offset+40])[0]
signature = data[fv_offset+40:fv_offset+44]
attributes = struct.unpack('<I', data[fv_offset+44:fv_offset+48])[0]
header_length = struct.unpack('<H', data[fv_offset+48:fv_offset+50])[0]

print(f"  ZeroVector: {zero_vector.hex()}")
print(f"  FileSystemGuid: {fs_guid.hex()}")
print(f"  FvLength: 0x{fv_length:X}")
print(f"  Signature: {signature}")
print(f"  Attributes: 0x{attributes:08X}")
print(f"  HeaderLength: 0x{header_length:X}")

# The FV length is 0x631000 which is reasonable
# Let's look for files in this FV
# EFI_FFS_FILE_HEADER:
# Name (16 bytes)
# IntegrityCheck (2 bytes)
# Type (1 byte)
# Attributes (1 byte)
# Size (3 bytes)
# State (1 byte)

file_offset = fv_offset + header_length
file_offset = (file_offset + 7) & ~7  # Align to 8 bytes

print(f"\nFiles in FV at 0x{fv_offset:X}:")
file_count = 0
while file_offset + 24 <= fv_offset + fv_length:
    name = data[file_offset:file_offset+16]
    integrity_check = struct.unpack('<H', data[file_offset+16:file_offset+18])[0]
    ftype = data[file_offset+18]
    attributes = data[file_offset+19]
    size = data[file_offset+20] | (data[file_offset+21] << 8) | (data[file_offset+22] << 16)
    state = data[file_offset+23]
    
    if size == 0 or size > fv_length or file_offset + size > fv_offset + fv_length:
        file_offset += 8
        continue
    
    # Validate file type
    valid_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xF0]
    if ftype in valid_types and size >= 24:
        file_count += 1
        name_hex = name.hex()
        
        # Check if file contains target strings
        file_data = data[file_offset:file_offset+size]
        has_targets = False
        targets_found = []
        for target in [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']:
            if target in file_data:
                targets_found.append(target.decode('latin-1'))
                has_targets = True
        
        if has_targets:
            print(f"  0x{file_offset:X}: Type=0x{ftype:02X}, Size=0x{size:X}, GUID={name_hex}, Targets={targets_found}")
        
        file_offset += size
        file_offset = (file_offset + 7) & ~7
    else:
        file_offset += 8
    
    if file_count > 10000:
        break

print(f"\nTotal files scanned: {file_count}")

