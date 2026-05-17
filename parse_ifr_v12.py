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

# Find the largest GuidDefinedSection object
largest = None

def find_largest(obj):
    global largest
    if hasattr(obj, 'data') and obj.data:
        if largest is None or len(obj.data) > len(largest.data):
            largest = obj
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            find_largest(child)

find_largest(firmware)

obj_data = largest.data

# The string package data looks encrypted or compressed.
# Let's look at the form packages instead.

# Form package at 0xFF7F9
fp_offset = 0xFF7F9
fp_length = 0x8200

pkg = obj_data[fp_offset:fp_offset+64]
print(f"Form package at offset 0x{fp_offset:X}:")
print(f"  Raw header: {pkg[:16].hex()}")

length = pkg[0] | (pkg[1] << 8) | (pkg[2] << 16)
pkg_type = pkg[3]
print(f"  Length: 0x{length:X}")
print(f"  Type: 0x{pkg_type:X}")
print(f"  Byte 4 (should be FORM_SET=0x01): 0x{pkg[4]:02X}")
print(f"  Bytes 4-20: {pkg[4:20].hex()}")

# This also looks encrypted/compressed. Let's think about this differently.
# The GuidDefinedSection might be using a specific GUID that indicates compression/encryption.

# Let's look at the GUID of the GuidDefinedSection
print(f"\nGuidDefinedSection GUID: {largest.guid.hex() if hasattr(largest, 'guid') else 'N/A'}")

# Common GUIDs for compressed sections:
# EFI_GUIDED_SECTION_LZMA_COMPRESS = EE4E5898-3914-4259-9D6E-DC7BD79403CF
# EFI_GUIDED_SECTION_TIANO_COMPRESS = A31280AD-481E-41B6-95E8-127F4C98477A

lzma_guid = bytes([0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF])
tiano_guid = bytes([0xAD, 0x80, 0x12, 0xA3, 0x1E, 0x48, 0xB6, 0x41, 0x95, 0xE8, 0x12, 0x7F, 0x4C, 0x98, 0x47, 0x7A])

print(f"LZMA GUID: {lzma_guid.hex()}")
print(f"Tiano GUID: {tiano_guid.hex()}")

if hasattr(largest, 'guid'):
    print(f"Section GUID: {largest.guid.hex()}")
    if largest.guid == lzma_guid:
        print("  -> This is an LZMA compressed section!")
    elif largest.guid == tiano_guid:
        print("  -> This is a Tiano compressed section!")

# Let's also check the parent FirmwareVolume GUID
# The FV with GUID ee4e5898-3914-4259-9d6e-dc7bd79403cf matches the LZMA GUID
# This means the section might be LZMA compressed.

# Let's try to decompress using the uefi_firmware library
print("\nTrying to process/decompress the section...")

# The uefi_firmware library might have already decompressed it
# Let's check if the data makes more sense at a different offset

# Search for "Setup" as UTF-16LE in the object
setup_utf16 = b'S\x00e\x00t\x00u\x00p\x00'
idx = obj_data.find(setup_utf16)
print(f"\n'Setup' (UTF-16LE) in object: {'found' if idx != -1 else 'not found'}")
if idx != -1:
    print(f"  at offset 0x{idx:X}")

# Let's look at the actual structure of the GuidDefinedSection
# It might have a header before the actual data
print(f"\nFirst 64 bytes of GuidDefinedSection data:")
for i in range(0, 64, 16):
    hex_part = ' '.join(f'{b:02X}' for b in obj_data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in obj_data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

