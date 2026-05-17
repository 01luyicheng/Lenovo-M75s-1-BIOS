import struct
import sys
import json

# The PE32 has a very small size_of_image (0x41600001) which is suspicious.
# This PE might be truncated or the size field is corrupted.
# Let's look at the actual PE more carefully.

pe_path = '/workspace/pe32_0x6D78F4.bin'

with open(pe_path, 'rb') as f:
    pe_data = f.read()

print(f"PE32 file size: {len(pe_data)} bytes")

# The size_of_image from the header is 0x41600001 which is > 1GB - impossible.
# This means the PE header is corrupted or this is not a real PE.
# But we found 'MZ' and 'PE' signatures...

# Let's look at the first 512 bytes of the PE
print("\nFirst 512 bytes:")
for i in range(0, 512, 16):
    hex_part = ' '.join(f'{b:02X}' for b in pe_data[i:i+16])
    ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pe_data[i:i+16])
    print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

# The PE header at offset 0xE8 shows:
# Let's verify the PE header
pe_offset = struct.unpack('<I', pe_data[0x3C:0x3C+4])[0]
print(f"\nPE offset: 0x{pe_offset:X}")
print(f"PE signature: {pe_data[pe_offset:pe_offset+4]}")

# COFF header
coff_offset = pe_offset + 4
machine = struct.unpack('<H', pe_data[coff_offset:coff_offset+2])[0]
num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
time_date_stamp = struct.unpack('<I', pe_data[coff_offset+4:coff_offset+8])[0]
print(f"Machine: 0x{machine:04X}")
print(f"Number of sections: {num_sections}")
print(f"TimeDateStamp: 0x{time_date_stamp:08X}")

# Optional header
oh_offset = coff_offset + 20
magic = struct.unpack('<H', pe_data[oh_offset:oh_offset+2])[0]
print(f"Magic: 0x{magic:04X}")

# For PE32+, the size_of_image is at offset 0x44 from optional header
if magic == 0x20b:
    size_of_image = struct.unpack('<I', pe_data[oh_offset+0x44:oh_offset+0x48])[0]
    print(f"SizeOfImage: 0x{size_of_image:08X}")
    
    # The section table starts at oh_offset + 240
    section_table_offset = oh_offset + 240
    print(f"Section table offset: 0x{section_table_offset:X}")
    
    # Parse sections
    for i in range(num_sections):
        sec_offset = section_table_offset + i * 40
        name = pe_data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virtual_size = struct.unpack('<I', pe_data[sec_offset+8:sec_offset+12])[0]
        virtual_address = struct.unpack('<I', pe_data[sec_offset+12:sec_offset+16])[0]
        raw_size = struct.unpack('<I', pe_data[sec_offset+16:sec_offset+20])[0]
        raw_address = struct.unpack('<I', pe_data[sec_offset+20:sec_offset+24])[0]
        print(f"  Section {i}: {name} VA=0x{virtual_address:08X} VS=0x{virtual_size:08X} RA=0x{raw_address:08X} RS=0x{raw_size:08X}")

# The size_of_image is indeed corrupted. Let's look at the raw data size instead.
# The file is 26MB, which is huge for a PE. This might actually be a firmware volume
# or a compressed blob that was misidentified as PE.

# Let's search for the actual PE boundaries by looking for the end of the last section
if magic == 0x20b:
    section_table_offset = oh_offset + 240
    max_end = 0
    for i in range(num_sections):
        sec_offset = section_table_offset + i * 40
        raw_size = struct.unpack('<I', pe_data[sec_offset+16:sec_offset+20])[0]
        raw_address = struct.unpack('<I', pe_data[sec_offset+20:sec_offset+24])[0]
        end = raw_address + raw_size
        if end > max_end:
            max_end = end
    
    print(f"\nActual PE data ends at offset: 0x{max_end:X}")
    print(f"But file size is: 0x{len(pe_data):X}")
    
    # The actual PE data is much smaller than the file size
    # Let's look at what comes after the PE data
    if max_end < len(pe_data):
        print(f"\nData after PE (first 256 bytes at offset 0x{max_end:X}):")
        for i in range(max_end, min(max_end + 256, len(pe_data)), 16):
            hex_part = ' '.join(f'{b:02X}' for b in pe_data[i:i+16])
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in pe_data[i:i+16])
            print(f"  0x{i:06X}: {hex_part:<48} {ascii_part}")

