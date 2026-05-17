import struct
import sys
import json

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# Let's analyze all FVs and find files with our target strings
fvs = [
    (0x0, 0x20000),
    (0x37000, 0x20000),
    (0x77000, 0x20000),
    (0x6CF000, 0x631000),
    (0xD00000, 0x300000),
    (0x1000000, 0x20000),
    (0x1037000, 0x20000),
    (0x1077000, 0x20000),
    (0x1411000, 0x8EF000),
]

targets = [b'Above 4G', b'IOMMU', b'SVM', b'SMT', b'Downcore', b'DownCore', b'ASPM', b'MemClk', b'PowerDown']

all_target_files = []

for fv_offset, fv_length in fvs:
    print(f"\n=== FV at 0x{fv_offset:X}, length=0x{fv_length:X} ===")
    
    file_offset = fv_offset + 0x48
    file_offset = (file_offset + 7) & ~7
    
    file_count = 0
    while file_offset + 24 <= fv_offset + fv_length:
        name = data[file_offset:file_offset+16]
        ftype = data[file_offset+18]
        attributes = data[file_offset+19]
        size = data[file_offset+20] | (data[file_offset+21] << 8) | (data[file_offset+22] << 16)
        state = data[file_offset+23]
        
        if size == 0 or size > fv_length or file_offset + size > fv_offset + fv_length:
            file_offset += 8
            continue
        
        valid_types = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xF0]
        if ftype in valid_types and size >= 24:
            file_count += 1
            file_data = data[file_offset:file_offset+size]
            
            targets_found = []
            for target in targets:
                if target in file_data:
                    targets_found.append(target.decode('latin-1'))
            
            if targets_found:
                print(f"  0x{file_offset:X}: Type=0x{ftype:02X}, Size=0x{size:X}, GUID={name.hex()}, Targets={targets_found}")
                all_target_files.append({
                    'fv_offset': fv_offset,
                    'file_offset': file_offset,
                    'type': ftype,
                    'size': size,
                    'guid': name.hex(),
                    'targets': targets_found,
                    'data': file_data
                })
            
            file_offset += size
            file_offset = (file_offset + 7) & ~7
        else:
            file_offset += 8
        
        if file_count > 10000:
            break

print(f"\n\n=== Summary ===")
print(f"Found {len(all_target_files)} files with target strings")

# Group by target
from collections import defaultdict
target_files = defaultdict(list)
for f in all_target_files:
    for t in f['targets']:
        target_files[t].append(f)

for target, files in target_files.items():
    print(f"\n{target}: {len(files)} files")
    for f in files:
        print(f"  0x{f['file_offset']:X}: Type=0x{f['type']:02X}, Size=0x{f['size']:X}")

