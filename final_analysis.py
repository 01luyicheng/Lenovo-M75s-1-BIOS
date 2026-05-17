import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# Since we can't decompress the VZL format, let's focus on what we CAN determine:
# 1. The ROM structure
# 2. The modules containing each setting
# 3. The NVAR/Setup variable structure
# 4. Potential modification approaches

# Let's analyze the Setup variable (NVAR) more carefully
# We found NVAR structures at 0x37090 and 0x1037090

print("=" * 70)
print("BIOS ROM STRUCTURE ANALYSIS")
print("=" * 70)

# FV layout
fvs = [
    (0x0, 0x20000, "Boot firmware volume"),
    (0x37000, 0x20000, "Secondary FV"),
    (0x77000, 0x20000, "Tertiary FV"),
    (0x6CF000, 0x631000, "Main firmware volume (AGESA/AMD modules)"),
    (0xD00000, 0x300000, "Setup/DXE firmware volume"),
    (0x1000000, 0x20000, "Recovery FV"),
    (0x1037000, 0x20000, "Secondary recovery FV"),
    (0x1077000, 0x20000, "Tertiary recovery FV"),
    (0x1411000, 0x8EF000, "Large data FV"),
]

print("\nFirmware Volumes:")
for offset, length, desc in fvs:
    print(f"  0x{offset:08X} - 0x{offset+length:08X}: {desc}")

# Setup-related modules
print("\n" + "=" * 70)
print("SETUP-RELATED MODULES")
print("=" * 70)

modules = [
    {"name": "AmdCcxZenRvPei", "offset": 0xD1BB08, "size": 0x3592, "settings": ["SMT", "DownCore"]},
    {"name": "AmdCcxZenZpPei", "offset": 0xD1F0A0, "size": 0x3732, "settings": ["SMT", "Downcore"]},
    {"name": "AmdMemCzPei", "offset": 0xD467E8, "size": 0x4445A, "settings": ["MemClk", "PowerDown"]},
    {"name": "AmdNbioIOMMUZPPei", "offset": 0xD9A698, "size": 0x45E, "settings": ["IOMMU"]},
    {"name": "AmdNbioPcieRVPei", "offset": 0xDB8B60, "size": 0xB2A6, "settings": ["ASPM"]},
    {"name": "AmdNbioPcieZPPei", "offset": 0xDC3E08, "size": 0xB336, "settings": ["ASPM"]},
    {"name": "AmdNbioSmuV10Pei", "offset": 0xDCF140, "size": 0x2D82, "settings": ["SMT", "DownCore"]},
    {"name": "AmdNbioSmuV9Pei", "offset": 0xDE0490, "size": 0x3552, "settings": ["SMT", "DownCore"]},
    {"name": "AmdSocAm4RvPei", "offset": 0xDEB8E8, "size": 0x5CCA, "settings": ["Above 4G", "DownCore"]},
    {"name": "AmdSocAm4SmPei", "offset": 0xDF15B8, "size": 0x5A52, "settings": ["Above 4G"]},
    {"name": "SVM FV Image", "offset": 0x709800, "size": 0x5219BB, "settings": ["SVM"]},
]

for mod in modules:
    print(f"\n{mod['name']}:")
    print(f"  Offset: 0x{mod['offset']:X}")
    print(f"  Size: 0x{mod['size']:X}")
    print(f"  Settings: {', '.join(mod['settings'])}")

# NVAR/Setup variable analysis
print("\n" + "=" * 70)
print("SETUP VARIABLE (NVAR) ANALYSIS")
print("=" * 70)

# The Setup variable is at offset 0x370B2 (and 0x10370B2)
# Let's look at its structure more carefully

setup_var_offset = 0x370B2
print(f"\nSetup variable at 0x{setup_var_offset:X}:")

# Look at the NVAR structure
# NVAR signature at 0x370A8: "NVAR" 
# But the actual Setup data starts at 0x370B2

# Let's look at the context
context = data[0x37090:0x37150]
print("Context (0x37090 - 0x37150):")
for i in range(0, len(context), 16):
    hex_part = ' '.join(f'{b:02X}' for b in context[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in context[i:i+16])
    print(f"  0x{0x37090+i:06X}: {hex_part:<48} {ascii_part}")

# The Setup variable data starts after "Setup\x00" at 0x370B8
# The data appears to be a bitmap of settings
setup_data_start = 0x370B8
setup_data = data[setup_data_start:setup_data_start+256]

print(f"\nSetup variable data (first 256 bytes at 0x{setup_data_start:X}):")
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02X}' for b in setup_data[i:i+16])
    print(f"  0x{setup_data_start+i:06X}: {hex_part}")

# The Setup variable appears to be a simple byte array
# Each byte represents a setting (0x00 = disabled, 0x01 = enabled, etc.)

# Let's look for patterns in the Setup data
print("\nSetup data analysis:")
print(f"  Total size appears to be around 0x400 bytes (based on NVAR structure)")
print(f"  First 32 bytes: {setup_data[:32].hex()}")

# The data shows a pattern of 0x00 and 0x01 values
# This is typical for a Setup variable where each byte controls a setting

# MODIFICATION APPROACHES
print("\n" + "=" * 70)
print("MODIFICATION APPROACHES")
print("=" * 70)

print("""
Since this is an AMD AGESA-based BIOS with a non-standard VZL compression
format for PEIM modules, direct IFR modification is not feasible without
the decompression algorithm.

However, several modification approaches are possible:

1. SETUP VARIABLE MODIFICATION (Recommended)
   - The Setup NVAR variable at 0x370B2 contains the configuration bitmap
   - Modify the appropriate byte to enable/disable settings
   - This requires knowing the exact offset for each setting
   
2. MODULE PATCHING
   - Patch the PEIM modules directly to remove SuppressIf/GrayOutIf checks
   - This requires decompressing the VZL format first
   
3. NVRAM DIRECT MODIFICATION
   - Use tools like AMIBCP or setup_var in GRUB to modify settings
   - This is the safest approach for end users

4. UEFI SHELL METHOD
   - Use setup_var commands in UEFI Shell
   - Read/write specific offsets in the Setup variable
""")

# Search for specific byte patterns that might indicate hidden settings
print("\n" + "=" * 70)
print("POTENTIAL HIDDEN SETTING INDICATORS")
print("=" * 70)

# In many BIOS implementations, hidden settings are controlled by:
# 1. A "show all" or "advanced" flag in the Setup variable
# 2. Specific byte values that enable additional menus

# Let's search for common patterns
patterns = {
    b'\x01\x00\x00\x00\x01\x01\x00\x00': "Potential enable pattern",
    b'ShowAll': "Show all settings flag",
    b'Advanced': "Advanced mode flag",
    b'Expert': "Expert mode flag",
    b'Debug': "Debug mode flag",
}

for pattern, desc in patterns.items():
    idx = data.find(pattern)
    if idx != -1:
        print(f"Found '{desc}' at 0x{idx:X}")

# Look for the Setup variable size
# The NVAR at 0x37090 has a size field
nvar_size = struct.unpack('<H', data[0x37090+4:0x37090+6])[0]
print(f"\nNVAR size field: 0x{nvar_size:X}")

# The Setup variable data size might be around 0x400 bytes
# Let's check the next NVAR to determine the boundary
next_nvar = data.find(b'NVAR', 0x370B2)
if next_nvar != -1:
    print(f"Next NVAR at: 0x{next_nvar:X}")
    print(f"Setup data size estimate: 0x{next_nvar - 0x370B2:X} bytes")

