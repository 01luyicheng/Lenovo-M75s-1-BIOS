import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The VZL format is not standard LZMA. Let's analyze it more carefully.
# Looking at the VZL header:
# 56 5a 4c 01 - "VZL\x01"
# 09 0b b8 01 - unknown parameters
# 60 04 00 00 - could be uncompressed size
# 20 03 00 00 - could be compressed size
# f8 66 d4 ff - could be an offset or checksum

# Let's look at multiple VZL files to find patterns
vzl_files = [
    {'offset': 0xD467E8 + 0x9C, 'size': 0x44394, 'name': 'AmdMemCzPei'},
    {'offset': 0xDB8B60 + 0x9C, 'size': 0xB1D4, 'name': 'AmdNbioPcieRVPei'},
    {'offset': 0xDC3E08 + 0x9C, 'size': 0xB264, 'name': 'AmdNbioPcieZPPei'},
]

print("VZL header comparison:")
for vzl in vzl_files:
    vzl_data = data[vzl['offset']:vzl['offset']+vzl['size']]
    print(f"\n{vzl['name']}:")
    print(f"  Total size: 0x{vzl['size']:X}")
    
    # The raw section header is 4 bytes
    # Then VZL data starts
    section_size = vzl_data[0] | (vzl_data[1] << 8) | (vzl_data[2] << 16)
    section_type = vzl_data[3]
    print(f"  Section: size=0x{section_size:X}, type=0x{section_type:02X}")
    
    # VZL header at offset 4
    vzl_header = vzl_data[4:28]
    print(f"  VZL header (24 bytes): {vzl_header.hex()}")
    
    # Parse potential fields
    field1 = struct.unpack('<H', vzl_header[0:2])[0]  # 0x090b
    field2 = struct.unpack('<H', vzl_header[2:4])[0]  # 0x01b8
    field3 = struct.unpack('<I', vzl_header[4:8])[0]  # 0x00000460
    field4 = struct.unpack('<I', vzl_header[8:12])[0]  # 0x00000320
    field5 = struct.unpack('<I', vzl_header[12:16])[0]  # 0xFFD466F8
    field6 = struct.unpack('<I', vzl_header[16:20])[0]  # 0x00000000
    field7 = struct.unpack('<I', vzl_header[20:24])[0]  # 0x00043C20
    
    print(f"  Field1: 0x{field1:04X}")
    print(f"  Field2: 0x{field2:04X}")
    print(f"  Field3: 0x{field3:08X}")
    print(f"  Field4: 0x{field4:08X}")
    print(f"  Field5: 0x{field5:08X}")
    print(f"  Field6: 0x{field6:08X}")
    print(f"  Field7: 0x{field7:08X}")
    
    # Let's see if field3 or field4 relate to sizes
    print(f"  Field3 decimal: {field3}")
    print(f"  Field4 decimal: {field4}")
    print(f"  Section size - 28: {section_size - 28}")
    
    # Check if field3 is close to uncompressed size and field4 to compressed size
    # For AmdMemCzPei: field3=0x460=1120, field4=0x320=800
    # But the section is 0x44394 bytes, so these are too small
    
    # Maybe the fields are in a different order
    # Let's look at the structure after the first 24 bytes
    # There might be section names or other metadata
    
    after_header = vzl_data[28:64]
    print(f"  After header (36 bytes): {after_header.hex()}")
    
    # Look for PE section names
    if b'.text' in vzl_data:
        print("  -> Contains '.text' section name")
    if b'.data' in vzl_data:
        print("  -> Contains '.data' section name")
    if b'.rdata' in vzl_data:
        print("  -> Contains '.rdata' section name")

# Let's try a completely different approach
# Maybe VZL is not compression but a custom executable format
# Let's look for x86 code patterns

print("\n\nLooking for x86 code patterns in VZL data:")
vzl_data = data[0xD467E8 + 0x9C:0xD467E8 + 0x9C + 0x44394]

# Look for common x86 prologues
prologue_patterns = [
    b'\x55\x8B\xEC',  # push ebp; mov ebp, esp
    b'\x48\x89\x5C',  # mov [rsp+...], rbx (x64)
    b'\x40\x53',      # push rbx (x64)
    b'\x48\x83\xEC',  # sub rsp, ... (x64)
]

for pattern in prologue_patterns:
    count = vzl_data.count(pattern)
    if count > 0:
        print(f"  Pattern {pattern.hex()}: {count} occurrences")

# The VZL format might be a custom format used by AMD/AMI
# Without knowing the exact format, we can't decompress it

# Let's focus on what we CAN extract from the ROM
# The debug strings we found earlier give us valuable information

print("\n\n=== Summary of findings from debug strings ===")

# Above 4G Decoding
print("\nAbove 4G Decoding:")
print("  Found in: AmdSocAm4RvPei, AmdSocAm4SmPei")
print("  Related strings: 'Above4GMmioSizePerRbForNonPciDevice'")
print("  This is an AMD AGESA setting for MMIO allocation above 4GB")

# IOMMU
print("\nIOMMU:")
print("  Found in: AmdNbioIOMMUZPPei")
print("  Related strings: 'IOMMU MMIO space', 'IommuEfr'")
print("  This is an AMD NBIO IOMMU setting")

# SVM Mode
print("\nSVM Mode:")
print("  Found in: SVM FV image (0x709800)")
print("  This is likely the AMD-V virtualization setting")

# SMT
print("\nSMT:")
print("  Found in: AmdCcxZenRvPei, AmdCcxZenZpPei, AmdNbioSmuV10Pei, AmdNbioSmuV9Pei")
print("  Related strings: 'Disabling SMT', 'SMT: APOB ThreadCount mismatch'")
print("  This is the Simultaneous Multi-Threading setting")

# DownCore
print("\nDownCore:")
print("  Found in: AmdCcxZenRvPei, AmdCcxZenZpPei, AmdNbioSmuV10Pei, AmdNbioSmuV9Pei, AmdSocAm4RvPei, AmdSocAm4SmPei")
print("  Related strings: 'DownCoreMode', 'CoreDisMask', 'Downcore mode (1+0) not supported'")
print("  This is the core disabling/downcore setting")

# ASPM
print("\nASPM:")
print("  Found in: AmdNbioPcieRVPei, AmdNbioPcieZPPei")
print("  Related strings: 'LinkAspm', 'ASPM - %a'")
print("  This is the PCIe ASPM setting")

# MemClk
print("\nMemory Clock / MemClk:")
print("  Found in: AmdMemCzPei")
print("  Related strings: 'MemClkFreq', 'Default MemClkFreq', 'MemClkFreq after platform limits'")
print("  This is the memory clock frequency setting")

# PowerDown
print("\nPower Down Mode:")
print("  Found in: AmdMemCzPei")
print("  Related strings: 'PowerDown', 'PowerDown : %d'")
print("  This is the DRAM power down mode setting")

