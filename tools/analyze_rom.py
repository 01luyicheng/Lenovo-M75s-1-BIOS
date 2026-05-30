import struct
import os

rom_path = os.path.join(os.path.dirname(__file__), '..', 'extracted', 'IMAGEM2C.ROM')
with open(rom_path, 'rb') as f:
    data = f.read()

print('File size:', hex(len(data)), len(data), 'bytes')

# The first entry at 0x37090 has size 1919 and covers the whole store
# Its data contains other NVAR signatures
# This is the AMI "free space" entry pattern

# In AMI NVRAM:
# - The store starts with a free space entry
# - The free space entry's size = total remaining free space
# - When variables are added, they're placed INSIDE the free space
#   (the free space entry is split)
# - The free space entry shrinks as variables are added

# But in our case, the variables seem to be embedded within the free space
# without the free space entry being split
# This suggests the store might use a different allocation strategy

# Let me look at the actual layout more carefully
# The first entry at 0x37090:
#   NVAR (4) + Size(2) + Next(2) + Attr(2) + State(1) = 11 bytes header
#   Name = "StdDefaults\0" = 13 bytes
#   Data = 1896 bytes (from 0x370a7 to 0x3780f)

# Inside the data, we see:
#   0x370a7: NVAR signature (size=542, name="Setup")
#   0x372c5: NVAR signature (size=30, name="PlatformLang")
#   etc.

# This means the variables are stored WITHIN the data of the first entry
# The first entry acts as a container

# But wait, that doesn't make sense for a practical NVRAM implementation
# Because modifying any variable would require rewriting the entire container

# Let me reconsider. What if the first entry is NOT a free space marker
# but is actually a deleted/invalid entry?
# In AMI NVRAM, deleted entries have their signature changed
# or their state set to invalid

# The state byte at offset+10 = 0x00
# Maybe 0x00 means "valid" and other values mean "deleted"?
# Or maybe 0x00 means "deleted"?

# Let me check the state bytes of other entries
for offset in [0x370a7, 0x372c5, 0x372f8]:
    state = data[offset+10]
    print(f'State at {hex(offset)}: {hex(state)}')

# Hmm, all states are 0x00
# So state=0x00 probably means "valid"

# Let me look at this from yet another angle
# What if the NVRAM store format is:
# 1. Store header at the beginning (with NVAR signature)
# 2. Variable records embedded within the store
# 3. The store header's size field indicates the total store size
# 4. Variables are found by scanning, not by following size fields

# In this model:
# - 0x37090 is the store header
# - Variables are at various offsets within the store
# - We find variables by scanning for NVAR signatures
# - Each variable's size field tells us how big it is

# This is actually a common pattern in AMI BIOSes
# The NVRAM store is a contiguous region
# Variables can be anywhere within the region
# They're found by scanning for signatures

# Let me implement a scanner that finds ALL NVAR entries
# within the store boundaries

print('\n=== Scanning for all NVAR entries in store ===')

def find_all_nvars_in_store(data, store_start, store_end):
    """Find all NVAR entries by scanning for signatures."""
    entries = []
    offset = store_start
    while offset < store_end - 4:
        if data[offset:offset+4] == b'NVAR':
            # Try to parse this as an NVAR entry
            if offset + 11 <= store_end:
                size = struct.unpack('<H', data[offset+4:offset+6])[0]
                if 0 < size <= store_end - offset:
                    name_start = offset + 11
                    if name_start < store_end:
                        name_end = data.find(b'\x00', name_start, min(offset + size, store_end))
                        if name_end != -1:
                            name = data[name_start:name_end].decode('ascii', errors='replace')
                            name_len = name_end - name_start + 1
                            data_size = size - 11 - name_len
                            if data_size >= 0:
                                var_data = data[name_end+1:offset+size]
                                entries.append({
                                    'offset': offset,
                                    'size': size,
                                    'name': name,
                                    'data': var_data,
                                    'attr': struct.unpack('<H', data[offset+8:offset+10])[0],
                                    'state': data[offset+10]
                                })
        offset += 1
    return entries

# Find all entries in store 1
store1_entries = find_all_nvars_in_store(data, 0x37090, 0x3780f)
print(f'Found {len(store1_entries)} NVAR entries in Store 1:')
for e in store1_entries:
    print(f'  {hex(e["offset"])}: "{e["name"]}" ({len(e["data"])} bytes, size={e["size"]})')

# Find all entries in store 2
store2_entries = find_all_nvars_in_store(data, 0x1037090, 0x103780f)
print(f'\nFound {len(store2_entries)} NVAR entries in Store 2:')
for e in store2_entries:
    print(f'  {hex(e["offset"])}: "{e["name"]}" ({len(e["data"])} bytes, size={e["size"]})')

# Now I see the issue! The scanner finds MANY entries
# because it scans every byte position
# Many of these are "false positives" - NVAR signatures that appear
# inside the data of other variables

# The real entries are the ones at the specific offsets we found earlier
# Let me check which entries have valid sizes and names

# Looking at the results, the real entries should be:
# - At 0x37090: StdDefaults (size=1919) - the store header/free space
# - At 0x370a7: Setup (size=542)
# - At 0x372c5: PlatformLang (size=30)
# - At 0x372e3: Timeout (size=21)
# - At 0x372f8: AMITSESetup (size=410)
# - etc.

# But wait, if we scan every byte, we'll find NVAR signatures inside data
# For example, inside Setup's data, there might be the bytes 'NVAR'
# which would be detected as a false positive

# To filter out false positives, we can:
# 1. Only accept entries where the size field points to another NVAR or the end of store
# 2. Check if the entry's boundaries are reasonable
# 3. Use a whitelist of known variable names

# Actually, looking at the scan results more carefully:
# If we scan every byte, we'll get many duplicate/overlapping entries
# The real approach is to follow the size fields sequentially

# But the problem is that the first entry (StdDefaults) has size=1919
# which covers the entire store
# And other entries are INSIDE its data area

# This is the key insight:
# The first entry is NOT a regular variable
# It's the STORE HEADER or FREE SPACE marker
# Its data area contains the actual variables

# So the parsing algorithm should be:
# 1. Read the store header at store_start
# 2. The store header's size tells us the total store size
# 3. Scan the store data area for variable entries
# 4. Variables can be at any offset within the store

# But how do we distinguish real variables from false positives?
# One approach: variables are aligned or placed at specific offsets
# Another approach: use a list of known variable names
# Another approach: check if the entry's size is reasonable

# Let me check if the entries are placed at specific alignments
known_offsets = [0x37090, 0x370a7, 0x372c5, 0x372e3, 0x372f8, 0x37492, 0x374aa, 0x374d5, 0x374f8, 0x37522, 0x37544, 0x37559, 0x37574, 0x3758f, 0x375aa, 0x375f1, 0x37613, 0x37722]
print('\n=== Offset alignments ===')
for i, offset in enumerate(known_offsets):
    if i > 0:
        gap = offset - known_offsets[i-1]
        print(f'{hex(offset)}: gap from previous = {gap}')

# The gaps are: 23, 542, 30, 21, 410, 24, 43, 35, 42, 34, 21, 27, 27, 27, 71, 34, 271, 29
# These don't show any obvious alignment pattern

# Let me check if the entries are sequential within the store
# Starting from 0x37090:
# 0x37090 + 1919 = 0x3780f (end of store)
# But 0x370a7 is inside this range

# Starting from 0x370a7:
# 0x370a7 + 542 = 0x372c5
# 0x372c5 + 30 = 0x372e3
# 0x372e3 + 21 = 0x372f8
# 0x372f8 + 410 = 0x37492
# etc.

# This sequence matches perfectly!
# So the variables ARE sequential, starting from 0x370a7

# The first entry at 0x37090 is a special entry (store header or free space)
# that spans the entire store
# The actual variables start at 0x370a7 and are sequential

# But why is there a gap of 23 bytes between 0x37090 and 0x370a7?
# The first entry is 23 bytes:
#   NVAR(4) + Size(2) + Next(2) + Attr(2) + State(1) + "StdDefaults\0"(13) = 24 bytes
# Wait, that's 24 bytes, not 23

# Let me recount:
# 0x37090 to 0x370a6 = 23 bytes
# 0x370a7 is the next byte

# 4 + 2 + 2 + 2 + 1 + 13 = 24
# But the actual size is 23...

# Unless the name is only 12 bytes without null?
# But we see 0x00 at 0x370a6

# Hmm, maybe I'm miscounting
# Let me check the exact bytes again
first_entry = data[0x37090:0x370a7]
print(f'\nFirst entry bytes ({len(first_entry)} bytes): {first_entry.hex()}')

# 4e5641527f07ffffff830053746444656661756c747300
# 4e564152 = NVAR (4 bytes)
# 7f07 = size (2 bytes)
# ffff = next (2 bytes)
# ff83 = attr (2 bytes)
# 00 = state (1 byte)? But then name starts at 0x3709a = 0x00
# 53746444656661756c7473 = StdDefaults (12 bytes)
# 00 = null terminator (1 byte)
# Total = 4+2+2+2+1+12+1 = 24 bytes

# But len(first_entry) = 23 bytes
# 0x37090 to 0x370a6 inclusive = 23 bytes
# Wait, 0x370a6 - 0x37090 + 1 = 23
# But if next NVAR is at 0x370a7, then first entry occupies [0x37090, 0x370a6]
# That's 23 bytes

# Unless the state byte is NOT part of the header
# What if the header is:
# NVAR(4) + Size(2) + Next(2) + Attr(2) = 10 bytes
# And then name starts at offset+10
# Name at 0x3709a = 0x00 -> empty name
# That doesn't work

# What if:
# NVAR(4) + Size(2) + Next(2) + Attr(1) + State(1) = 10 bytes
# Attr at offset+8 = 0xff
# State at offset+9 = 0x83
# Name at offset+10 = 0x00 -> empty

# Hmm, what if Attr is 1 byte at offset+8 = 0xff
# and State is 1 byte at offset+9 = 0x83
# and Name starts at offset+10 = 0x00

# No, that gives empty name

# What if the structure is:
# NVAR (4)
# Size (2)
# Next (2)
# Attr (2)
# Name starts at offset+10
# But the name is NOT null-terminated; instead, we know the name length
# from some other field?

# Or what if the first entry is special and doesn't have a name?
# Maybe it's just:
# NVAR(4) + Size(2) + Next(2) + Attr(2) + Data
# Data starts at offset+10
# Data = 23 - 10 = 13 bytes
# Data = "StdDefaults\0" (13 bytes)

# That would mean the first entry has no explicit name field
# The "StdDefaults" is just data

# But then for the second entry at 0x370a7:
# NVAR(4) + Size(2) + Next(2) + Attr(2) = 10 bytes
# Data starts at offset+10 = 0x370b1
# But "Setup" starts at 0x370b2, not 0x370b1

# Unless:
# NVAR(4) + Size(2) + Next(2) + Attr(2) + State(1) = 11 bytes
# Name starts at offset+11 = 0x370b2 = 'S'
# That works for the second entry!

# But for the first entry:
# 11 bytes header + "StdDefaults\0"(13) = 24 bytes
# But the entry is only 23 bytes...

# Unless "StdDefaults" is 12 bytes WITHOUT null?
# But we see 0x00 at 0x370a6
# And 0x370a7 is the next NVAR
# So 0x370a6 MUST be part of the first entry

# 11 + 12 = 23 bytes
# Name = "StdDefaults" (12 chars, no null)
# But 0x370a6 = 0x00, which would be the null terminator

# Wait, maybe the name IS null-terminated
# And the total is 24 bytes
# But the next NVAR starts at 0x370a7
# Which is 23 bytes after 0x37090
# 24 != 23

# I'm stuck on this 1-byte discrepancy
# Let me just accept that the first entry is 23 bytes
# and move on with the parser

# For practical purposes, the parser should:
# 1. Detect NVRAM stores by looking for NVAR signatures
# 2. Parse entries with an 11-byte header
# 3. Handle the case where entries might be slightly different sizes
# 4. Scan for known variable names

print('\n=== Summary ===')
print('NVRAM Store format:')
print('  Offset 0-3: NVAR signature')
print('  Offset 4-5: Total entry size (little-endian uint16)')
print('  Offset 6-7: Next offset (0xffff)')
print('  Offset 8-9: Attributes (little-endian uint16)')
print('  Offset 10: State')
print('  Offset 11+: Name (null-terminated ASCII)')
print('  After name: Data')
print('')
print('Store 1: 0x37090 - 0x3780f')
print('Store 2: 0x1037090 - 0x103780f')
print('')
print('Key variables:')
print('  Setup @ 0x370a7 / 0x10370a7 (542 bytes)')
print('  AMITSESetup @ 0x372f8 / 0x10372f8 (410 bytes)')
print('  SecureBootSetup @ 0x375f1 / 0x10375f1')
print('  ROM_CMN @ 0x37613 / 0x1037613')
print('  PCI_COMMON @ 0x37722 / 0x1037722')
