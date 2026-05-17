import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The raw sections start with "VZL" which is likely a compressed format.
# "VZL" could be a custom compression used by AMI/AMD.
# Let's analyze the VZL format.

# VZL header:
# "VZL" (3 bytes) + version (1 byte) + ...

# Let's look at the MemClk/PowerDown file since it's the largest
memclk_offset = 0xD467E8
memclk_size = 0x4445A
memclk_data = data[memclk_offset:memclk_offset+memclk_size]

# The raw section starts at offset 0x9C in the file
raw_offset = 0x9C
raw_data = memclk_data[raw_offset:]

print("MemClk/PowerDown raw section analysis:")
print(f"  First 64 bytes: {raw_data[:64].hex()}")
print(f"  Signature: {raw_data[:3]}")
print(f"  Version: 0x{raw_data[3]:02X}")

# The signature is "VZL" with version 0x01
# Let's look at the structure
# After "VZL\x01", there might be compression parameters
print(f"  Bytes 4-16: {raw_data[4:16].hex()}")

# Let's check if it's LZMA or another common compression
# LZMA typically starts with 5 bytes of properties + 8 bytes of uncompressed size
# But VZL might be a wrapper

# Let's look at all the VZL files and see if we can find patterns
vzl_files = [
    {'offset': 0xD1BB08 + 0xAC, 'size': 0x34B4, 'name': 'AmdCcxZenRvPei'},
    {'offset': 0xD1F0A0 + 0xAC, 'size': 0x3654, 'name': 'AmdCcxZenZpPei'},
    {'offset': 0xD467E8 + 0x9C, 'size': 0x44394, 'name': 'AmdMemCzPei'},
    {'offset': 0xD9A698 + 0x64, 'size': 0x3C4, 'name': 'AmdNbioIOMMUZPPei'},
    {'offset': 0xDB8B60 + 0x9C, 'size': 0xB1D4, 'name': 'AmdNbioPcieRVPei'},
    {'offset': 0xDC3E08 + 0x9C, 'size': 0xB264, 'name': 'AmdNbioPcieZPPei'},
    {'offset': 0xDCF140 + 0x78, 'size': 0x2CD4, 'name': 'AmdNbioSmuV10Pei'},
    {'offset': 0xDE0490 + 0x9C, 'size': 0x3484, 'name': 'AmdNbioSmuV9Pei'},
    {'offset': 0xDEB8E8 + 0x54, 'size': 0x5C44, 'name': 'AmdSocAm4RvPei'},
    {'offset': 0xDF15B8 + 0x54, 'size': 0x59CC, 'name': 'AmdSocAm4SmPei'},
]

print("\nVZL file analysis:")
for vzl in vzl_files:
    vzl_data = data[vzl['offset']:vzl['offset']+vzl['size']]
    print(f"\n{vzl['name']}:")
    print(f"  Size: 0x{vzl['size']:X}")
    print(f"  First 32 bytes: {vzl_data[:32].hex()}")
    
    # Parse VZL header
    if vzl_data[:3] == b'VZL':
        version = vzl_data[3]
        print(f"  VZL version: 0x{version:02X}")
        
        # The next bytes seem to be:
        # 0x05 0x0B 0xB8 0x01 ...
        # This might be compression parameters
        
        # Let's look for PE signature after decompression
        # The VZL data might decompress to a PE32 image
        
        # For now, let's just save the VZL data
        with open(f"/workspace/vzl_{vzl['name']}.bin", 'wb') as f:
            f.write(vzl_data)

# Let's also look at the SVM FV image more carefully
# It contains a GUID-defined section with LZMA compression
svm_offset = 0x709800
svm_size = 0x5219BB
svm_data = data[svm_offset:svm_offset+svm_size]

# The first section is GUID-defined (type 0x02)
# GUID: 98584eee143959429d6edc7bd79403cf (LZMA)
# Data offset: 0x18
# Attributes: 0x0001

guid_data = svm_data[0x18:]
print(f"\n\nSVM LZMA data first 64 bytes: {guid_data[:64].hex()}")

# The LZMA data starts with properties byte
# Properties: lc, lp, pb encoded in first byte
# Then dictionary size (4 bytes)
# Then uncompressed size (8 bytes)

# Let's try to decompress using Python's lzma
import lzma

try:
    # Standard LZMA format
    decompressed = lzma.decompress(guid_data)
    print(f"Decompressed size: {len(decompressed)} bytes")
    print(f"First 64 bytes: {decompressed[:64].hex()}")
    
    # Save decompressed data
    with open('/workspace/svm_decompressed.bin', 'wb') as f:
        f.write(decompressed)
except Exception as e:
    print(f"Standard LZMA decompression failed: {e}")
    
    # Try LZMA without header
    try:
        # Create a filter with default properties
        filters = [{"id": lzma.FILTER_LZMA1, "dict_size": 0x10000}]
        decompressed = lzma.decompress(guid_data, format=lzma.FORMAT_RAW, filters=filters)
        print(f"Raw LZMA decompressed size: {len(decompressed)} bytes")
    except Exception as e2:
        print(f"Raw LZMA decompression failed: {e2}")

