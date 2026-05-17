import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# The NVAR parsing is tricky. Let's take a step back and focus on what we can do:
# 1. Search for target strings in the raw ROM
# 2. Analyze the context around them to understand the data structure
# 3. Look for SuppressIf/GrayOutIf patterns

# Let's search for our target strings and show more context
targets = {
    'Above 4G Decoding': b'Above 4G Decoding',
    'Above4G': b'Above4G',
    'IOMMU': b'IOMMU',
    'SVM Mode': b'SVM Mode',
    'SMT Mode': b'SMT Mode',
    'Downcore': b'Downcore',
    'DownCore': b'DownCore',
    'Down Core': b'Down Core',
    'ASPM': b'ASPM',
    'PCIe Link Speed': b'PCIe Link Speed',
    'Memory Clock': b'Memory Clock',
    'MemClk': b'MemClk',
    'Power Down Mode': b'Power Down Mode',
    'PowerDown': b'PowerDown',
}

results = {}
for name, pattern in targets.items():
    idx = data.find(pattern)
    if idx != -1:
        results[name] = idx
        print(f"\n{'='*60}")
        print(f"Found '{name}' at offset 0x{idx:X}")
        print(f"{'='*60}")
        
        # Show 128 bytes before and after
        start = max(0, idx - 128)
        end = min(len(data), idx + len(pattern) + 128)
        print(f"Context (0x{start:X} - 0x{end:X}):")
        for i in range(start, end, 16):
            hex_part = ' '.join(f'{b:02X}' for b in data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
            print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# Let's also search for "SuppressIf" and "GrayOutIf" as ASCII
target_conditions = [b'SuppressIf', b'GrayOutIf', b'DisableIf', b'ReadOnly', b'Locked']
print("\n\nSearching for condition keywords:")
for cond in target_conditions:
    idx = data.find(cond)
    if idx != -1:
        print(f"Found '{cond.decode()}' at 0x{idx:X}")

# Search for "Form" and "Question" related strings
print("\nSearching for IFR-related strings:")
ifr_strings = [b'Form ', b'Question ', b'VarStore ', b'OneOf ', b'Checkbox ', b'Numeric ']
for s in ifr_strings:
    count = data.count(s)
    if count > 0:
        print(f"'{s.decode()}' found {count} times")

