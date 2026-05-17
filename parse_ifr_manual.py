import struct
import sys
import re
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# IFR opcodes (UEFI spec)
IFR_FORM_SET = 0x01
IFR_FORM = 0x02
IFR_SUBTITLE = 0x02  # same as form? No, different
IFR_TEXT = 0x03
IFR_IMAGE = 0x04
IFR_ONE_OF = 0x05
IFR_CHECKBOX = 0x06
IFR_NUMERIC = 0x07
IFR_PASSWORD = 0x08
IFR_ONE_OF_OPTION = 0x09
IFR_SUPPRESS_IF = 0x0A
IFR_LOCKED = 0x0B
IFR_ACTION = 0x0C
IFR_RESET_BUTTON = 0x0D
IFR_FORM_MAP = 0x0E
IFR_STATEMENT = 0x0F
IFR_GRAY_OUT_IF = 0x19
IFR_VARSTORE = 0x24
IFR_VARSTORE_NAME_VALUE = 0x25
IFR_VARSTORE_EFI = 0x26
IFR_VARSTORE_DEVICE = 0x27
IFR_END = 0x29
IFR_ONE_OF_OPTION_2 = 0x30  # newer

# EFI_HII_PACKAGE_HEADER signature
EFI_HII_PACKAGE_FORM = 0x02

# Search for HII form packages
# HII package header: Length(3 bytes) + Type(1 byte)
# For form packages, Type = 0x02

def find_hii_form_packages(data):
    packages = []
    i = 0
    while i < len(data) - 4:
        # Check for potential HII package header
        length = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
        pkg_type = data[i+3]
        
        if pkg_type == EFI_HII_PACKAGE_FORM and length > 4 and length < 0x100000 and i + length <= len(data):
            # Validate: should start with IFR_FORM_SET (0x01) after header
            if i + 4 < len(data) and data[i+4] == IFR_FORM_SET:
                packages.append((i, length))
                print(f"Found HII Form package at offset 0x{i:X}, length {length}")
                i += length
                continue
        i += 1
    return packages

# Better approach: search for IFR opcodes directly
# Look for FORM_SET opcode (0x01) followed by GUID

def find_ifr_sequences(data):
    sequences = []
    i = 0
    while i < len(data) - 16:
        if data[i] == IFR_FORM_SET:
            # Check if it looks like a valid FORM_SET
            # EFI_IFR_FORM_SET: Opcode(1) + Length(2) + Scope(1) + Guid(16) + Title(2) + ...
            length = data[i+1] | (data[i+2] << 8)
            scope = data[i+3]
            if length >= 21 and length < 0x200 and scope == 0x01:
                # Could be valid
                sequences.append((i, 'FORM_SET', length))
        elif data[i] == IFR_VARSTORE:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 24 and length < 0x100:
                sequences.append((i, 'VARSTORE', length))
        elif data[i] == IFR_SUPPRESS_IF:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 5 and length < 0x100:
                sequences.append((i, 'SUPPRESS_IF', length))
        elif data[i] == IFR_GRAY_OUT_IF:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 5 and length < 0x100:
                sequences.append((i, 'GRAY_OUT_IF', length))
        elif data[i] == IFR_ONE_OF:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 14 and length < 0x200:
                sequences.append((i, 'ONE_OF', length))
        elif data[i] == IFR_CHECKBOX:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 14 and length < 0x200:
                sequences.append((i, 'CHECKBOX', length))
        elif data[i] == IFR_NUMERIC:
            length = data[i+1] | (data[i+2] << 8)
            if length >= 18 and length < 0x200:
                sequences.append((i, 'NUMERIC', length))
        i += 1
    return sequences

print("\nSearching for IFR sequences...")
sequences = find_ifr_sequences(data)
print(f"Found {len(sequences)} potential IFR opcodes")

# Print first 50
for seq in sequences[:50]:
    print(f"  0x{seq[0]:X}: {seq[1]} (len={seq[2]})")

# Search for specific strings and their surrounding context
keywords = [
    b'Above 4G Decoding', b'Above4G', b'Above 4G',
    b'IOMMU', b'Iommu',
    b'SVM Mode', b'SVM mode', b'SVM',
    b'SMT Mode', b'SMT mode', b'SMT',
    b'Downcore', b'DownCore', b'Down Core',
    b'ASPM',
    b'PCIe Link Speed', b'PCIe Speed', b'Link Speed',
    b'Memory Clock', b'MemClk', b'Mem Clk',
    b'Power Down Mode', b'PowerDown', b'Power Down'
]

print("\n\nSearching for keywords in binary...")
for kw in keywords:
    idx = data.find(kw)
    if idx != -1:
        print(f"Found '{kw.decode('latin-1', errors='replace')}' at offset 0x{idx:X}")
        # Show surrounding context
        start = max(0, idx - 64)
        end = min(len(data), idx + len(kw) + 64)
        context = data[start:end]
        # Try to decode as UTF-16LE
        try:
            decoded = context.decode('utf-16-le', errors='ignore')
            # Filter printable
            printable = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in decoded)
            print(f"  Context (UTF-16LE): {printable[:200]}")
        except:
            try:
                decoded = context.decode('ascii', errors='ignore')
                printable = ''.join(c if c.isprintable() or c in '\n\r\t' else '.' for c in decoded)
                print(f"  Context (ASCII): {printable[:200]}")
            except:
                print(f"  Context (hex): {context.hex()[:200]}")

