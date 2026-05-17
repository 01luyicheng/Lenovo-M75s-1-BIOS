import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The files have section type 0x1B which is not standard UEFI.
# Let's look at what section types are present.
# In some BIOS implementations, section type 0x1B might be a custom type.

# Let's look at the SVM file (0x709800) more carefully since it's an FV image (type 0x0B)
# and might contain the actual Setup data

svm_offset = 0x709800
svm_size = 0x5219BB
svm_data = data[svm_offset:svm_offset+svm_size]

print("SVM file analysis:")
print(f"  First 64 bytes: {svm_data[:64].hex()}")

# The first section has type 0x02 which is EFI_SECTION_GUID_DEFINED
# Let's parse it
section_size = svm_data[24] | (svm_data[25] << 8) | (svm_data[26] << 16)
section_type = svm_data[27]
print(f"  First section: size=0x{section_size:X}, type=0x{section_type:02X}")

# For GUID-defined sections, the GUID is at offset 28
if section_type == 0x02 and len(svm_data) > 44:
    guid = svm_data[28:44]
    print(f"  GUID: {guid.hex()}")
    
    # Data offset and attributes
    data_offset = struct.unpack('<H', svm_data[44:46])[0]
    attributes = struct.unpack('<H', svm_data[46:48])[0]
    print(f"  Data offset: 0x{data_offset:X}")
    print(f"  Attributes: 0x{attributes:04X}")
    
    # The actual data starts at data_offset
    actual_data = svm_data[data_offset:]
    print(f"  Actual data size: {len(actual_data)} bytes")
    print(f"  First 64 bytes of actual data: {actual_data[:64].hex()}")
    
    # Check if it's an FV
    if actual_data[40:44] == b'_FVH':
        print("  -> Contains an FV!")
        
        # Parse the FV
        fv_offset_in_data = 0
        fv_length = struct.unpack('<Q', actual_data[32:40])[0]
        fv_header_length = struct.unpack('<H', actual_data[48:50])[0]
        print(f"  FV length: 0x{fv_length:X}")
        print(f"  FV header length: 0x{fv_header_length:X}")
        
        # Look for files in this FV
        file_offset = fv_header_length
        file_offset = (file_offset + 7) & ~7
        
        while file_offset + 24 <= fv_length:
            name = actual_data[file_offset:file_offset+16]
            ftype = actual_data[file_offset+18]
            fsize = actual_data[file_offset+20] | (actual_data[file_offset+21] << 8) | (actual_data[file_offset+22] << 16)
            
            if fsize == 0 or fsize > fv_length or file_offset + fsize > fv_length:
                file_offset += 8
                continue
            
            valid_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xF0]
            if ftype in valid_types and fsize >= 24:
                file_data = actual_data[file_offset:file_offset+fsize]
                
                # Check for target strings
                targets_found = []
                for target in [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']:
                    if target in file_data:
                        targets_found.append(target.decode('latin-1'))
                
                if targets_found:
                    print(f"    File at 0x{file_offset:X}: Type=0x{ftype:02X}, Size=0x{fsize:X}, Targets={targets_found}")
                
                file_offset += fsize
                file_offset = (file_offset + 7) & ~7
            else:
                file_offset += 8

# Let's also look at the PEIM files more carefully
# The section type 0x1B might be a compressed section

print("\n\nAnalyzing PEIM file at 0xD1BB08 (SMT/DownCore):")
peim_offset = 0xD1BB08
peim_size = 0x3592
peim_data = data[peim_offset:peim_offset+peim_size]

# The file has section type 0x1B at offset 27
# Let's look at all sections in this file
print("  Sections:")
sec_offset = 24
while sec_offset < peim_size:
    if sec_offset + 4 > peim_size:
        break
    sec_size = peim_data[sec_offset] | (peim_data[sec_offset+1] << 8) | (peim_data[sec_offset+2] << 16)
    sec_type = peim_data[sec_offset+3]
    print(f"    offset=0x{sec_offset:X}, size=0x{sec_size:X}, type=0x{sec_type:02X}")
    
    if sec_size == 0 or sec_size > peim_size - sec_offset:
        break
    
    sec_offset += sec_size
    sec_offset = (sec_offset + 3) & ~3

