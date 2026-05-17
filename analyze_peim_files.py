import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# We found the files! They are PEIMs (Type 0x06) and FV images (Type 0x0B)
# Let's analyze each one to find the actual Setup IFR data

# The files we care about:
target_files = [
    {'offset': 0x709800, 'size': 0x5219BB, 'type': 0x0B, 'targets': ['SVM']},
    {'offset': 0xD1BB08, 'size': 0x3592, 'type': 0x06, 'targets': ['SMT', 'DownCore']},
    {'offset': 0xD1F0A0, 'size': 0x3732, 'type': 0x06, 'targets': ['SMT', 'Downcore']},
    {'offset': 0xD467E8, 'size': 0x4445A, 'type': 0x06, 'targets': ['MemClk', 'PowerDown']},
    {'offset': 0xD9A698, 'size': 0x45E, 'type': 0x06, 'targets': ['IOMMU']},
    {'offset': 0xDB8B60, 'size': 0xB2A6, 'type': 0x06, 'targets': ['ASPM']},
    {'offset': 0xDC3E08, 'size': 0xB336, 'type': 0x06, 'targets': ['ASPM']},
    {'offset': 0xDCF140, 'size': 0x2D82, 'type': 0x06, 'targets': ['SMT', 'DownCore']},
    {'offset': 0xDE0490, 'size': 0x3552, 'type': 0x06, 'targets': ['SMT', 'DownCore']},
    {'offset': 0xDEB8E8, 'size': 0x5CCA, 'type': 0x06, 'targets': ['Above 4G', 'DownCore']},
    {'offset': 0xDF15B8, 'size': 0x5A52, 'type': 0x06, 'targets': ['Above 4G']},
]

# For each file, check if it contains a PE image and extract it
for tf in target_files:
    print(f"\n{'='*60}")
    print(f"File at 0x{tf['offset']:X}, size=0x{tf['size']:X}, type=0x{tf['type']:02X}")
    print(f"Targets: {tf['targets']}")
    print(f"{'='*60}")
    
    file_data = data[tf['offset']:tf['offset']+tf['size']]
    
    # Check for PE signature
    if file_data[:2] == b'MZ':
        print("  Has MZ header")
        if len(file_data) > 0x3C + 4:
            pe_offset = struct.unpack('<I', file_data[0x3C:0x3C+4])[0]
            if pe_offset + 4 <= len(file_data) and file_data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                print(f"  Has PE signature at offset 0x{pe_offset:X}")
    
    # Check for section headers
    # For type 0x06 (PEIM), the file might have a section header before the PE
    # EFI_FFS_FILE_HEADER is 24 bytes, then sections follow
    
    # Let's look at the first 64 bytes
    print(f"  First 64 bytes: {file_data[:64].hex()}")
    
    # For PEIM files, they typically have:
    # - EFI_FFS_FILE_HEADER (24 bytes)
    # - EFI_COMMON_SECTION_HEADER (4 bytes) for PE32 section
    # - PE32 image
    
    # Check for section type 0x10 (PE32)
    if len(file_data) > 28:
        section_size = file_data[24] | (file_data[25] << 8) | (file_data[26] << 16)
        section_type = file_data[27]
        print(f"  First section: size=0x{section_size:X}, type=0x{section_type:02X}")
        
        if section_type == 0x10 and section_size > 0:
            pe_data = file_data[24:24+section_size]
            if pe_data[:2] == b'MZ':
                print(f"  -> Contains PE32 image in section")
                # Save the PE
                with open(f"/workspace/peim_0x{tf['offset']:X}.bin", 'wb') as f:
                    f.write(pe_data)
                print(f"  Saved PE to /workspace/peim_0x{tf['offset']:X}.bin")
    
    # Also check for compressed sections (type 0x14 = GUID-defined)
    if len(file_data) > 28:
        section_type = file_data[27]
        if section_type == 0x14:
            print("  -> Contains GUID-defined section (possibly compressed)")
            # The GUID is at offset 28
            if len(file_data) > 44:
                guid = file_data[28:44]
                print(f"  GUID: {guid.hex()}")

