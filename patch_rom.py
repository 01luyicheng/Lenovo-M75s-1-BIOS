#!/usr/bin/env python3
"""
Patch the ROM to unlock hidden advanced menus.

Strategy:
1. We work directly on the ROM file
2. We find form packages in the ROM and patch SuppressIf/GrayOutIf conditions
3. We avoid PSP regions

The main DXE volume starts at ROM offset 0x4 (based on info.txt).
But we need to find the exact location of form packages in the ROM.
"""

import struct
import os
import shutil

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"
PATCHED_ROM_PATH = "/workspace/bios_extracted/IMAGEM2C_patched.rom"

def find_form_packages_in_rom(rom_data):
    """Find HII form packages directly in the ROM."""
    packages = []
    i = 0
    while i < len(rom_data) - 4:
        pkg_type = rom_data[i]
        pkg_len = struct.unpack('<I', rom_data[i:i+3] + b'\x00')[0] & 0xFFFFFF
        if pkg_type == 0x02 and pkg_len >= 8 and pkg_len < 0x100000 and i + pkg_len <= len(rom_data):
            first_op = rom_data[i+4] & 0x7F if i+4 < len(rom_data) else 0
            if first_op == 0x32:  # FORM_SET
                packages.append((i, pkg_len))
                i += pkg_len
                continue
        i += 1
    return packages

def scan_for_conditions_in_range(rom_data, start, end):
    """Scan for SuppressIf/GrayOutIf in a specific ROM range."""
    results = []
    i = start
    while i < end - 2:
        op = rom_data[i] & 0x7F
        scope = (rom_data[i] & 0x80) != 0
        length = rom_data[i+1]

        if op in (0x0A, 0x0B) and 3 <= length <= 64:
            if i + length <= end:
                cond = rom_data[i+3:i+length]
                results.append({
                    'offset': i,
                    'type': 'SUPPRESS_IF' if op == 0x0A else 'GRAY_OUT_IF',
                    'scope': scope,
                    'length': length,
                    'opcode_byte': rom_data[i],
                    'cond': cond,
                    'raw': bytes(rom_data[i:i+length])
                })
                i += length
                continue
        i += 1
    return results

def find_psp_regions(rom_data):
    """Find PSP regions to avoid patching them."""
    psp_regions = []
    i = 0
    while i < len(rom_data) - 4:
        # Look for $PSP header signature
        if rom_data[i:i+4] == b'$PSP':
            # PSP directory header: signature(4) + checksum(4) + num_entries(4) + ...
            if i + 8 <= len(rom_data):
                num_entries = struct.unpack('<I', rom_data[i+8:i+12])[0]
                size = 0x10 + num_entries * 0x10
                psp_regions.append((i, size))
                i += size
                continue
        i += 1
    return psp_regions

def is_in_psp_region(offset, psp_regions):
    """Check if an offset is within a PSP region."""
    for start, size in psp_regions:
        if start <= offset < start + size:
            return True
    return False

def find_patchable_conditions(conditions, psp_regions, rom_data):
    """Find conditions that can be patched to always show menus."""
    patchable = []

    for c in conditions:
        off = c['offset']

        # Skip if in PSP region
        if is_in_psp_region(off, psp_regions):
            continue

        # Also skip if near PSP regions (safety margin)
        near_psp = False
        for psp_start, psp_size in psp_regions:
            if abs(off - psp_start) < 0x1000:
                near_psp = True
                break
        if near_psp:
            continue

        cond = c['cond']

        # Pattern 1: SuppressIf with TRUE condition (0x01)
        if len(cond) >= 2 and cond[0] == 0x01:
            patchable.append({
                'offset': off + 3,
                'original': 0x01,
                'new': 0x00,
                'reason': f"{c['type']} with TRUE -> FALSE",
                'context': c['raw'].hex()
            })

        # Pattern 2: Empty condition
        elif len(cond) == 0:
            patchable.append({
                'offset': off,
                'original': c['opcode_byte'],
                'new': 0x39,
                'reason': f"{c['type']} empty -> END_IF",
                'context': c['raw'].hex()
            })

        # Pattern 3: Access check with EQUAL
        elif len(cond) >= 6:
            has_eq = 0x18 in cond
            has_qref = 0x5E in cond
            has_uint = any(b in cond for b in (0x5A, 0x5B, 0x5C, 0x5D))

            if has_eq and has_qref and has_uint:
                eq_offset = None
                for j, b in enumerate(cond):
                    if b == 0x18:
                        eq_offset = j
                        break
                if eq_offset is not None:
                    patchable.append({
                        'offset': off + 3 + eq_offset,
                        'original': 0x18,
                        'new': 0x19,
                        'reason': f"{c['type']} access check invert",
                        'context': c['raw'].hex()
                    })

    return patchable

def main():
    with open(ROM_PATH, 'rb') as f:
        rom_data = bytearray(f.read())

    print(f"ROM size: {len(rom_data)} bytes")

    # Find PSP regions
    psp_regions = find_psp_regions(rom_data)
    print(f"Found {len(psp_regions)} PSP regions:")
    for start, size in psp_regions:
        print(f"  0x{start:08X} - 0x{start+size:08X} (size {size})")

    # Find form packages in ROM
    pkgs = find_form_packages_in_rom(rom_data)
    print(f"\nFound {len(pkgs)} form packages in ROM")

    all_conditions = []
    for off, size in pkgs:
        conditions = scan_for_conditions_in_range(rom_data, off, off + size)
        all_conditions.extend(conditions)
        print(f"  Package at 0x{off:08X}: {len(conditions)} conditions")

    print(f"\nTotal conditions found: {len(all_conditions)}")

    # Find patchable targets
    patchable = find_patchable_conditions(all_conditions, psp_regions, rom_data)
    print(f"Patchable conditions (excluding PSP): {len(patchable)}")

    # Show some examples
    print("\n--- Sample patchable conditions ---")
    for p in patchable[:30]:
        print(f"  0x{p['offset']:08X}: {p['reason']}")
        print(f"    0x{p['original']:02X} -> 0x{p['new']:02X}")

    # Apply patches
    print("\n" + "=" * 70)
    print("Applying patches...")
    print("=" * 70)

    patches_applied = []
    patches_skipped = []

    for p in patchable:
        off = p['offset']
        original = rom_data[off]
        if original != p['original']:
            patches_skipped.append({
                'offset': off,
                'expected': p['original'],
                'found': original,
                'reason': p['reason']
            })
        else:
            rom_data[off] = p['new']
            patches_applied.append(p)

    print(f"Patches applied: {len(patches_applied)}")
    print(f"Patches skipped (mismatch): {len(patches_skipped)}")

    if patches_skipped:
        print("\nSkipped patches:")
        for p in patches_skipped[:10]:
            print(f"  0x{p['offset']:08X}: expected 0x{p['expected']:02X}, found 0x{p['found']:02X}")

    # Save patched ROM
    with open(PATCHED_ROM_PATH, 'wb') as f:
        f.write(rom_data)

    print(f"\nPatched ROM saved to: {PATCHED_ROM_PATH}")

    # Verify
    print("\nVerifying patches...")
    with open(PATCHED_ROM_PATH, 'rb') as f:
        verify_data = f.read()

    verify_ok = 0
    verify_fail = 0
    for p in patches_applied[:20]:
        val = verify_data[p['offset']]
        if val == p['new']:
            verify_ok += 1
        else:
            verify_fail += 1
            print(f"  FAIL at 0x{p['offset']:08X}: expected 0x{p['new']:02X}, got 0x{val:02X}")

    if verify_fail == 0:
        print(f"  All {verify_ok} verified patches OK")

    # Save patch log
    with open('/workspace/patch_log.txt', 'w') as f:
        f.write("BIOS Patch Log\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"Original ROM: {ROM_PATH}\n")
        f.write(f"Patched ROM: {PATCHED_ROM_PATH}\n")
        f.write(f"ROM size: {len(rom_data)} bytes\n\n")
        f.write(f"PSP regions found: {len(psp_regions)}\n")
        for start, size in psp_regions:
            f.write(f"  0x{start:08X} - 0x{start+size:08X}\n")
        f.write(f"\nForm packages: {len(pkgs)}\n")
        f.write(f"Total conditions: {len(all_conditions)}\n")
        f.write(f"Patchable conditions: {len(patchable)}\n")
        f.write(f"Patches applied: {len(patches_applied)}\n")
        f.write(f"Patches skipped: {len(patches_skipped)}\n\n")

        f.write("All patches applied:\n")
        for p in patches_applied:
            f.write(f"  Offset: 0x{p['offset']:08X}\n")
            f.write(f"    Change: 0x{p['original']:02X} -> 0x{p['new']:02X}\n")
            f.write(f"    Reason: {p['reason']}\n")
            f.write(f"    Context: {p['context']}\n")

    print("\nPatch log saved to: /workspace/patch_log.txt")

if __name__ == '__main__':
    main()
