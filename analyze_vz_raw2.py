import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# Looking at the VZL data more carefully:
# The first 2 bytes seem to be the size of something
# Then "VZL" + version
# Let's parse the VZL header more carefully

# Example: 94430412565a4c01090bb8016004000020030000f866d4ff00000000203c0400
# 94 43 - could be a size or checksum
# 04 12 - could be section info
# 56 5a 4c 01 - "VZL\x01"
# 09 0b b8 01 - compression parameters?
# 60 04 00 00 - could be uncompressed size
# 20 03 00 00 - could be compressed size
# f8 66 d4 ff - could be an offset

# Let's look at the structure more carefully
vzl_offset = 0xD467E8 + 0x9C
vzl_data = data[vzl_offset:vzl_offset+0x44394]

print("VZL header analysis:")
print(f"  Bytes 0-2: {vzl_data[0:3]} (should be size or something)")
print(f"  Bytes 3-5: {vzl_data[3:6].hex()}")
print(f"  Bytes 6-9: {vzl_data[6:10]} (VZL signature?)")

# Actually, looking at the pattern:
# 94430412 565a4c01 090bb801 60040000 20030000 f866d4ff 00000000 203c0400
# The VZL signature is at offset 4: 56 5a 4c 01 = "VZL\x01"
# Before that: 94 43 04 12 - this might be a section header

# Let's look at the section header format
# EFI_COMMON_SECTION_HEADER: Size(3 bytes) + Type(1 byte)
# Size = 0x129443 (but this is too big)
# Or Size = 0x043494 (also too big)

# Wait, the section size in the file header was 0x44394
# And the first 4 bytes are: 94 43 04 12
# If we read as little-endian 24-bit + 8-bit type:
# Size = 0x120443 (no)
# Or maybe it's: Type=0x12, Size=0x044394 (yes!)

section_type = vzl_data[3]
section_size = vzl_data[0] | (vzl_data[1] << 8) | (vzl_data[2] << 16)
print(f"\n  Section type: 0x{section_type:02X}")
print(f"  Section size: 0x{section_size:X}")

# Type 0x12 is EFI_SECTION_RAW
# So the raw section contains VZL compressed data starting at offset 4
# But wait, the file header said the section size is 0x44394
# And 0x044394 != 0x44394
# Let's check: the file section size was 0x44394 (from the file header)
# And the raw data size should be 0x44394 - 4 = 0x44390

# Actually, looking at the file header again:
# offset=0x9C, size=0x44394, type=0x12
# The section size includes the 4-byte header
# So the raw data size is 0x44394 - 4 = 0x44390

# But the first 4 bytes of raw data are: 94 43 04 12
# This doesn't look like VZL data
# Let's check if the VZL signature is elsewhere

# Search for "VZL" in the raw data
vzl_sig_positions = []
idx = 0
while True:
    idx = vzl_data.find(b'VZL', idx)
    if idx == -1:
        break
    vzl_sig_positions.append(idx)
    idx += 1

print(f"\nFound 'VZL' at {len(vzl_sig_positions)} positions in raw data")
for pos in vzl_sig_positions[:10]:
    print(f"  offset {pos}: {vzl_data[pos:pos+16].hex()}")

# Let's look at the actual VZL data
# The first VZL signature is at offset 4
if vzl_sig_positions:
    vzl_start = vzl_sig_positions[0]
    print(f"\nVZL data at offset {vzl_start}:")
    print(f"  Signature: {vzl_data[vzl_start:vzl_start+4]}")
    print(f"  Next 16 bytes: {vzl_data[vzl_start+4:vzl_start+20].hex()}")
    
    # Let's try to understand the VZL format
    # VZL\x01 followed by:
    # 09 0b b8 01 - could be: compressed_size_high, compressed_size_low, uncompressed_size_high, uncompressed_size_low?
    # Or it could be LZMA properties
    
    # Let's look at the LZMA properties interpretation
    # First byte after VZL: 0x09
    # In LZMA, properties = lc + lp*9 + pb*9*5
    # 0x09 = lc=1, lp=0, pb=1 (since 1 + 0*9 + 1*45 = 46, not 9)
    # Or lc=0, lp=1, pb=0 (since 0 + 1*9 + 0 = 9) - this works!
    
    # So: lc=0, lp=1, pb=0
    # Next 4 bytes: dictionary size (little-endian)
    dict_size = struct.unpack('<I', vzl_data[vzl_start+5:vzl_start+9])[0]
    print(f"  Dictionary size: 0x{dict_size:X}")
    
    # Next 8 bytes: uncompressed size
    uncompressed_size = struct.unpack('<Q', vzl_data[vzl_start+9:vzl_start+17])[0]
    print(f"  Uncompressed size: 0x{uncompressed_size:X}")
    
    # The compressed data starts at offset 17
    compressed_data = vzl_data[vzl_start+17:]
    print(f"  Compressed data size: {len(compressed_data)} bytes")
    
    # Try to decompress with LZMA
    import lzma
    
    # Create LZMA properties
    props = bytes([0x09])  # lc=0, lp=1, pb=0
    dict_size_bytes = struct.pack('<I', dict_size)
    uncompressed_size_bytes = struct.pack('<Q', uncompressed_size)
    
    # Standard LZMA header: props + dict_size + uncompressed_size
    lzma_header = props + dict_size_bytes + uncompressed_size_bytes
    
    try:
        decompressed = lzma.decompress(lzma_header + compressed_data)
        print(f"  Decompressed size: {len(decompressed)} bytes")
        print(f"  First 64 bytes: {decompressed[:64].hex()}")
        
        # Check if it's a PE
        if decompressed[:2] == b'MZ':
            print("  -> Decompressed to PE32!")
        
        with open('/workspace/vzl_decompressed.bin', 'wb') as f:
            f.write(decompressed)
    except Exception as e:
        print(f"  Decompression failed: {e}")
        
        # Try with different parameters
        try:
            filters = [{"id": lzma.FILTER_LZMA1, "dict_size": dict_size, "lc": 0, "lp": 1, "pb": 0}]
            decompressed = lzma.decompress(compressed_data, format=lzma.FORMAT_RAW, filters=filters)
            print(f"  Raw LZMA decompressed size: {len(decompressed)} bytes")
            print(f"  First 64 bytes: {decompressed[:64].hex()}")
            
            with open('/workspace/vzl_decompressed_raw.bin', 'wb') as f:
                f.write(decompressed)
        except Exception as e2:
            print(f"  Raw LZMA decompression failed: {e2}")

