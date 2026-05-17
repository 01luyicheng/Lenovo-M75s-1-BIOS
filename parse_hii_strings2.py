import struct
import sys
import json

# The HII string package parsing is failing because the data doesn't look like
# a standard UEFI HII string package. Let's examine the raw bytes more carefully.

pkg_path = '/workspace/hii_pe32_0x6D78F4_pkg1_type4.bin'

with open(pkg_path, 'rb') as f:
    pkg_data = f.read()

print(f"Package size: {len(pkg_data)} bytes")

# Let's look at the first 256 bytes
print("First 256 bytes:")
for i in range(0, 256, 16):
    hex_part = ' '.join(f'{b:02X}' for b in pkg_data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pkg_data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# The header says length=0xDA6850 and type=0x04, but the rest doesn't match
# standard HII string package format.
# Let's search for UTF-16LE strings directly in the package

print("\n\nSearching for UTF-16LE strings:")
utf16_strings = []
i = 0
while i < len(pkg_data) - 2:
    if pkg_data[i] != 0 and pkg_data[i+1] == 0 and 32 <= pkg_data[i] < 127:
        start = i
        while i < len(pkg_data) - 1 and pkg_data[i] != 0 and pkg_data[i+1] == 0 and 32 <= pkg_data[i] < 127:
            i += 2
        if i - start >= 4:
            s = pkg_data[start:i].decode('utf-16-le', errors='ignore')
            if len(s) >= 2 and all(c.isprintable() or c.isspace() for c in s):
                utf16_strings.append((start, s))
    i += 1

print(f"Found {len(utf16_strings)} UTF-16LE strings")
for offset, s in utf16_strings[:50]:
    print(f"  0x{offset:06X}: {s}")

# Let's also search for ASCII strings
print("\n\nSearching for ASCII strings:")
ascii_strings = []
i = 0
while i < len(pkg_data):
    if 32 <= pkg_data[i] < 127:
        start = i
        while i < len(pkg_data) and 32 <= pkg_data[i] < 127:
            i += 1
        if i - start >= 4:
            s = pkg_data[start:i].decode('ascii', errors='ignore')
            ascii_strings.append((start, s))
    i += 1

print(f"Found {len(ascii_strings)} ASCII strings")
for offset, s in ascii_strings[:50]:
    print(f"  0x{offset:06X}: {s}")

