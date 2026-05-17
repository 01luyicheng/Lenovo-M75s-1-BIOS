import struct
import sys
import json

# The "HII package" we extracted is actually x86 code, not HII data.
# The length field we read was actually x86 instructions.
# Let's go back to the PE32 and look for the actual HII data more carefully.

pe_path = '/workspace/pe32_0x6D78F4.bin'

with open(pe_path, 'rb') as f:
    pe_data = f.read()

print(f"PE32 size: {len(pe_data)} bytes")

# In a PE32 image, HII data is typically in a resource section or in a specific data section.
# Let's parse the PE headers to find sections.

# DOS header
pe_offset = struct.unpack('<I', pe_data[0x3C:0x3C+4])[0]
print(f"PE header offset: 0x{pe_offset:X}")

# PE signature
print(f"PE signature: {pe_data[pe_offset:pe_offset+4]}")

# COFF header
coff_offset = pe_offset + 4
num_sections = struct.unpack('<H', pe_data[coff_offset+2:coff_offset+4])[0]
print(f"Number of sections: {num_sections}")

# Optional header
oh_offset = coff_offset + 20
magic = struct.unpack('<H', pe_data[oh_offset:oh_offset+2])[0]
print(f"Optional header magic: 0x{magic:04X}")

if magic == 0x10b:
    # PE32
    section_table_offset = oh_offset + 224
    size_of_image = struct.unpack('<I', pe_data[oh_offset+0x38:oh_offset+0x3C])[0]
elif magic == 0x20b:
    # PE32+
    section_table_offset = oh_offset + 240
    size_of_image = struct.unpack('<I', pe_data[oh_offset+0x44:oh_offset+0x48])[0]
else:
    print("Unknown magic")
    sys.exit(1)

print(f"Size of image: 0x{size_of_image:X}")

# Parse section table
sections = []
for i in range(num_sections):
    sec_offset = section_table_offset + i * 40
    name = pe_data[sec_offset:sec_offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
    virtual_size = struct.unpack('<I', pe_data[sec_offset+8:sec_offset+12])[0]
    virtual_address = struct.unpack('<I', pe_data[sec_offset+12:sec_offset+16])[0]
    raw_size = struct.unpack('<I', pe_data[sec_offset+16:sec_offset+20])[0]
    raw_address = struct.unpack('<I', pe_data[sec_offset+20:sec_offset+24])[0]
    
    sections.append({
        'name': name,
        'virtual_size': virtual_size,
        'virtual_address': virtual_address,
        'raw_size': raw_size,
        'raw_address': raw_address
    })

print("\nSections:")
for sec in sections:
    print(f"  {sec['name']}: VA=0x{sec['virtual_address']:08X}, VS=0x{sec['virtual_size']:08X}, RA=0x{sec['raw_address']:08X}, RS=0x{sec['raw_size']:08X}")

# Look for HII data in each section
# HII packages typically start with a 4-byte header: Length(3) + Type(1)
# Type 0x02 = Form package, Type 0x04 = String package

print("\nSearching for HII packages in sections:")
for sec in sections:
    if sec['raw_size'] == 0:
        continue
    
    sec_data = pe_data[sec['raw_address']:sec['raw_address']+sec['raw_size']]
    
    # Search for HII package signatures
    i = 0
    while i < len(sec_data) - 4:
        length = sec_data[i] | (sec_data[i+1] << 8) | (sec_data[i+2] << 16)
        pkg_type = sec_data[i+3]
        
        if pkg_type in [0x02, 0x04] and length >= 0x10 and length <= len(sec_data) - i:
            if pkg_type == 0x02:
                # Form package should start with FORM_SET (0x01)
                if i + 4 < len(sec_data) and sec_data[i+4] == 0x01:
                    form_set_len = sec_data[i+5] | (sec_data[i+6] << 8)
                    if form_set_len >= 21 and form_set_len < 0x200:
                        print(f"  Section {sec['name']}: Form package at offset 0x{i:X}, len=0x{length:X}")
                        i += length
                        continue
            elif pkg_type == 0x04:
                # String package - check if it looks valid
                if i + 6 < len(sec_data):
                    hdr_size = sec_data[i+4] | (sec_data[i+5] << 8)
                    if hdr_size < length and hdr_size > 0:
                        print(f"  Section {sec['name']}: String package at offset 0x{i:X}, len=0x{length:X}")
                        i += length
                        continue
        i += 1

