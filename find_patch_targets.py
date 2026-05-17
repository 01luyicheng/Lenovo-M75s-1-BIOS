#!/usr/bin/env python3
"""
Find specific patch targets in the ROM:
1. SuppressIf with TRUE condition (change to FALSE to show menu)
2. SuppressIf with simple conditions that hide advanced menus
3. Access level checks

We focus on the main DXE volume body.bin which contains the actual IFR forms.
"""

import struct
import os
import shutil

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"
PATCHED_ROM_PATH = "/workspace/bios_extracted/IMAGEM2C_patched.rom"

# The main DXE volume with form packages
MAIN_BODY = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom.dump/28 4F1C52D3-D824-4D2A-A2F0-EC40C23C5916/13 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/1 Volume image section/0 5C60F367-A505-419A-859E-2A4FF6CA6FE5/body.bin"

def find_form_packages(data, base_offset=0):
    packages = []
    i = 0
    while i < len(data) - 4:
        pkg_type = data[i]
        pkg_len = struct.unpack('<I', data[i:i+3] + b'\x00')[0] & 0xFFFFFF
        if pkg_type == 0x02 and pkg_len >= 8 and pkg_len < 0x100000 and i + pkg_len <= len(data):
            first_op = data[i+4] & 0x7F if i+4 < len(data) else 0
            if first_op == 0x32:
                packages.append((base_offset + i, pkg_len))
                i += pkg_len
                continue
        i += 1
    return packages

def scan_for_suppress_if(data, base_offset=0):
    """Scan for SuppressIf (0x0A) and GrayOutIf (0x0B) opcodes with their conditions."""
    results = []
    i = 0
    while i < len(data) - 2:
        op = data[i] & 0x7F
        scope = (data[i] & 0x80) != 0
        length = data[i+1]

        if op in (0x0A, 0x0B) and 3 <= length <= 64:
            if i + length <= len(data):
                cond = data[i+3:i+length]
                results.append({
                    'offset': base_offset + i,
                    'type': 'SUPPRESS_IF' if op == 0x0A else 'GRAY_OUT_IF',
                    'scope': scope,
                    'length': length,
                    'opcode_byte': data[i],
                    'cond': cond,
                    'raw': data[i:i+length]
                })
                i += length
                continue
        i += 1
    return results

def find_patchable_conditions(conditions):
    """Find conditions that can be patched to always show menus."""
    patchable = []

    for c in conditions:
        cond = c['cond']
        off = c['offset']

        # Pattern 1: SuppressIf with TRUE condition (0x01)
        # Change TRUE to FALSE to stop suppression
        if len(cond) >= 2 and cond[0] == 0x01:
            patchable.append({
                'offset': off + 3,  # offset of TRUE opcode in condition
                'original': 0x01,
                'new': 0x00,
                'reason': f"{c['type']} with TRUE condition -> change to FALSE (always show)",
                'context': c['raw'].hex()
            })

        # Pattern 2: SuppressIf with empty/single-byte condition that evaluates to true
        # Some have just a TRUE or a single comparison
        elif len(cond) == 0:
            # Empty condition - the SuppressIf itself is the issue
            # We can change the opcode from SuppressIf to something harmless
            # But better: change the opcode byte to disable it
            patchable.append({
                'offset': off,
                'original': c['opcode_byte'],
                'new': 0x39,  # END_IF (harmless no-op in this context)
                'reason': f"{c['type']} with empty condition -> change to END_IF",
                'context': c['raw'].hex()
            })

        # Pattern 3: SuppressIf with FALSE condition - already showing, skip
        elif len(cond) >= 2 and cond[0] == 0x00:
            pass  # Already FALSE, no patch needed

        # Pattern 4: SuppressIf checking a variable with EQUAL
        # Pattern: UINT8(val) QUESTION_REF1(qid) EQUAL
        # or: QUESTION_REF1(qid) UINT8(val) EQUAL
        # We can change the condition to always FALSE
        elif len(cond) >= 6:
            has_eq = 0x18 in cond
            has_qref = 0x5E in cond
            has_uint = any(b in cond for b in (0x5A, 0x5B, 0x5C, 0x5D))

            if has_eq and has_qref and has_uint:
                # This is likely an access level check
                # Change the EQUAL to NOT_EQUAL to invert the logic
                # OR change the whole condition to FALSE
                eq_offset = None
                for j, b in enumerate(cond):
                    if b == 0x18:
                        eq_offset = j
                        break
                if eq_offset is not None:
                    patchable.append({
                        'offset': off + 3 + eq_offset,
                        'original': 0x18,
                        'new': 0x19,  # NOT_EQUAL - inverts the condition
                        'reason': f"{c['type']} with access check -> invert EQUAL to NOT_EQUAL",
                        'context': c['raw'].hex()
                    })

    return patchable

def main():
    with open(MAIN_BODY, 'rb') as f:
        body_data = f.read()

    print(f"Main body size: {len(body_data)} bytes")

    # Find form packages
    pkgs = find_form_packages(body_data)
    print(f"Form packages: {len(pkgs)}")

    all_conditions = []
    for off, size in pkgs:
        pkg_data = body_data[off:off+size]
        conditions = scan_for_suppress_if(pkg_data, off)
        all_conditions.extend(conditions)

    print(f"Total SuppressIf/GrayOutIf found: {len(all_conditions)}")

    # Categorize
    suppress = [c for c in all_conditions if c['type'] == 'SUPPRESS_IF']
    gray = [c for c in all_conditions if c['type'] == 'GRAY_OUT_IF']
    print(f"  SuppressIf: {len(suppress)}")
    print(f"  GrayOutIf: {len(gray)}")

    # Analyze conditions
    print("\n--- SuppressIf conditions ---")
    for c in suppress[:50]:
        cond = c['cond']
        if len(cond) == 0:
            desc = "empty"
        elif cond[0] == 0x01:
            desc = "TRUE"
        elif cond[0] == 0x00:
            desc = "FALSE"
        elif cond[0] == 0x5A:
            desc = f"UINT8({cond[2]})" if len(cond) > 2 else "UINT8"
        elif cond[0] == 0x5E:
            desc = f"QREF1" if len(cond) > 2 else "QREF1"
        elif cond[0] == 0x18:
            desc = "EQUAL"
        elif cond[0] == 0x19:
            desc = "NOT_EQUAL"
        else:
            desc = f"OP_{cond[0]:02X}"
        print(f"  0x{c['offset']:06X}: {desc:20s} len={c['length']:2d} raw={cond.hex()}")

    print("\n--- GrayOutIf conditions ---")
    for c in gray[:50]:
        cond = c['cond']
        if len(cond) == 0:
            desc = "empty"
        elif cond[0] == 0x01:
            desc = "TRUE"
        elif cond[0] == 0x00:
            desc = "FALSE"
        elif cond[0] == 0x5A:
            desc = f"UINT8({cond[2]})" if len(cond) > 2 else "UINT8"
        elif cond[0] == 0x5E:
            desc = f"QREF1" if len(cond) > 2 else "QREF1"
        elif cond[0] == 0x18:
            desc = "EQUAL"
        elif cond[0] == 0x19:
            desc = "NOT_EQUAL"
        else:
            desc = f"OP_{cond[0]:02X}"
        print(f"  0x{c['offset']:06X}: {desc:20s} len={c['length']:2d} raw={cond.hex()}")

    # Find patchable targets
    print("\n" + "=" * 70)
    print("Finding patchable targets...")
    print("=" * 70)

    patchable = find_patchable_conditions(all_conditions)
    print(f"Found {len(patchable)} patchable conditions")

    for p in patchable[:50]:
        print(f"  ROM offset 0x{p['offset']:08X}: {p['reason']}")
        print(f"    Change 0x{p['original']:02X} -> 0x{p['new']:02X}")
        print(f"    Context: {p['context']}")

    # Now we need to map body.bin offsets to ROM offsets
    # The body.bin is inside a specific FFS file in the ROM
    # We need to find where this body.bin starts in the ROM

    # Read the ROM
    with open(ROM_PATH, 'rb') as f:
        rom_data = bytearray(f.read())

    # Find the body.bin content in the ROM
    body_start_in_rom = rom_data.find(body_data)
    if body_start_in_rom == -1:
        print("\nWARNING: Could not find body.bin in ROM directly!")
        print("Trying to find via the extracted path...")

        # The body.bin is at a specific offset based on the UEFI structure
        # Let's use the info.txt files to find the exact ROM offset
        info_path = os.path.join(os.path.dirname(MAIN_BODY), "info.txt")
        if os.path.exists(info_path):
            with open(info_path, 'r') as f:
                info = f.read()
            print(f"Info: {info}")
    else:
        print(f"\nbody.bin found in ROM at offset: 0x{body_start_in_rom:08X}")

        # Calculate ROM offsets for patches
        rom_patches = []
        for p in patchable:
            rom_offset = body_start_in_rom + p['offset']
            rom_patches.append({
                'rom_offset': rom_offset,
                'original': p['original'],
                'new': p['new'],
                'reason': p['reason']
            })

        print(f"\nTotal ROM patches to apply: {len(rom_patches)}")
        for p in rom_patches[:30]:
            print(f"  ROM 0x{p['rom_offset']:08X}: 0x{p['original']:02X} -> 0x{p['new']:02X} | {p['reason']}")

        # Apply patches
        print("\nApplying patches...")
        shutil.copy(ROM_PATH, PATCHED_ROM_PATH)

        with open(PATCHED_ROM_PATH, 'r+b') as f:
            for p in rom_patches:
                f.seek(p['rom_offset'])
                original = f.read(1)[0]
                if original != p['original']:
                    print(f"  WARNING at 0x{p['rom_offset']:08X}: expected 0x{p['original']:02X}, got 0x{original:02X}")
                else:
                    f.seek(p['rom_offset'])
                    f.write(bytes([p['new']]))
                    print(f"  Patched 0x{p['rom_offset']:08X}: 0x{p['original']:02X} -> 0x{p['new']:02X}")

        print(f"\nPatched ROM saved to: {PATCHED_ROM_PATH}")

        # Verify
        print("\nVerifying patches...")
        with open(PATCHED_ROM_PATH, 'rb') as f:
            for p in rom_patches[:10]:
                f.seek(p['rom_offset'])
                val = f.read(1)[0]
                status = "OK" if val == p['new'] else "FAIL"
                print(f"  0x{p['rom_offset']:08X}: 0x{val:02X} [{status}]")

if __name__ == '__main__':
    main()
