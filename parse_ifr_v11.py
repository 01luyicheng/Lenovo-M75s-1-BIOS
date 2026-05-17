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

# Let's examine the first string package more carefully
sp_offset = 0x102
sp_length = 0xD28FA

pkg = obj_data[sp_offset:sp_offset+64]
print(f"String package at offset 0x{sp_offset:X}:")
print(f"  Raw header: {pkg[:16].hex()}")

length = pkg[0] | (pkg[1] << 8) | (pkg[2] << 16)
pkg_type = pkg[3]
print(f"  Length: 0x{length:X}")
print(f"  Type: 0x{pkg_type:X}")

# The HII string package format might be different.
# Let's look at the raw bytes after the header
print(f"  Bytes 4-20: {pkg[4:20].hex()}")
print(f"  Bytes 20-40: {pkg[20:40].hex()}")

# Let's try to find UTF-16LE strings directly in the package
print("\nSearching for UTF-16LE strings in first string package:")
utf16_strings = []
i = 4
while i < sp_length - 2:
    # Look for printable UTF-16LE strings
    if pkg[i] != 0 and pkg[i+1] == 0 and 32 <= pkg[i] < 127:
        start = i
        while i < sp_length - 1 and pkg[i] != 0 and pkg[i+1] == 0 and 32 <= pkg[i] < 127:
            i += 2
        if i - start >= 4:  # At least 2 chars
            s = obj_data[sp_offset+start:sp_offset+i].decode('utf-16-le', errors='ignore')
            utf16_strings.append((start, s))
    i += 1

print(f"Found {len(utf16_strings)} UTF-16LE strings")
for offset, s in utf16_strings[:30]:
    print(f"  offset 0x{offset:X}: {s}")

# Let's also try a different approach - search for the string blocks directly
# In HII string packages, strings are stored in blocks with type bytes.
# But maybe the format is simpler - just raw UTF-16LE strings.

# Let's search for our target keywords as UTF-16LE in the entire object
print("\n\nSearching for target keywords as UTF-16LE in entire object:")
targets_utf16 = {
    'Above 4G Decoding': b'A\x00b\x00o\x00v\x00e\x00 \x004\x00G\x00 \x00D\x00e\x00c\x00o\x00d\x00i\x00n\x00g\x00',
    'Above4G': b'A\x00b\x00o\x00v\x00e\x004\x00G\x00',
    'IOMMU': b'I\x00O\x00M\x00M\x00U\x00',
    'SVM Mode': b'S\x00V\x00M\x00 \x00M\x00o\x00d\x00e\x00',
    'SMT Mode': b'S\x00M\x00T\x00 \x00M\x00o\x00d\x00e\x00',
    'Downcore': b'D\x00o\x00w\x00n\x00c\x00o\x00r\x00e\x00',
    'DownCore': b'D\x00o\x00w\x00n\x00C\x00o\x00r\x00e\x00',
    'Down Core': b'D\x00o\x00w\x00n\x00 \x00C\x00o\x00r\x00e\x00',
    'ASPM': b'A\x00S\x00P\x00M\x00',
    'PCIe Link Speed': b'P\x00C\x00I\x00e\x00 \x00L\x00i\x00n\x00k\x00 \x00S\x00p\x00e\x00e\x00d\x00',
    'Memory Clock': b'M\x00e\x00m\x00o\x00r\x00y\x00 \x00C\x00l\x00o\x00c\x00k\x00',
    'MemClk': b'M\x00e\x00m\x00C\x00l\x00k\x00',
    'Power Down Mode': b'P\x00o\x00w\x00e\x00r\x00 \x00D\x00o\x00w\x00n\x00 \x00M\x00o\x00d\x00e\x00',
    'PowerDown': b'P\x00o\x00w\x00e\x00r\x00D\x00o\x00w\x00n\x00',
}

for name, pattern in targets_utf16.items():
    idx = obj_data.find(pattern)
    if idx != -1:
        print(f"Found '{name}' at offset 0x{idx:X}")

