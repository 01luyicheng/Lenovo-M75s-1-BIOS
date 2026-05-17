#!/usr/bin/env python3
"""
UEFI IFR opcode analyzer for hidden menu unlocking.
Searches for SuppressIf (0x0A), GrayOutIf (0x0B), DisableIf (0x1C) opcodes
and identifies conditions that hide advanced menus.
"""

import sys
import struct
import os

# IFR opcodes we care about
OP_SUPPRESS_IF = 0x0A
OP_GRAY_OUT_IF = 0x0B
OP_DISABLE_IF = 0x1C
OP_FORM = 0x01
OP_FORM_END = 0x02
OP_REF = 0x0F
OP_END_IF = 0x09
OP_TRUE = 0x46
OP_FALSE = 0x47
OP_EQ = 0x2F
OP_AND = 0x15
OP_OR = 0x16
OP_NOT = 0x17
OP_ONE = 0x55
OP_ZERO = 0x52
OP_UINT8 = 0x30
OP_UINT16 = 0x31
OP_UINT32 = 0x32
OP_UINT64 = 0x33
OP_QUESTION_REF1 = 0x40
OP_QUESTION_REF2 = 0x41
OP_VARSTORE = 0x24
OP_VARSTORE_NAME_VALUE = 0x25
OP_VARSTORE_EFI = 0x26

def read_file(path):
    with open(path, 'rb') as f:
        return f.read()

def find_ifr_packages(data):
    """Find IFR form packages by looking for EFI_HII_PACKAGE_FORM (0x02) signatures."""
    # HII package header: type (1 byte), length (3 bytes)
    # Type 0x02 = Forms package
    packages = []
    i = 0
    while i < len(data) - 4:
        pkg_type = data[i]
        pkg_len = struct.unpack('<I', data[i:i+3] + b'\x00')[0] & 0xFFFFFF
        if pkg_type == 0x02 and pkg_len > 4 and pkg_len < 0x100000 and i + pkg_len <= len(data):
            # Validate: first opcode should be FORM_SET (0x0E) or similar
            op = data[i+4]
            if op in (0x0E, 0x01, 0x0A, 0x0B, 0x1C):
                packages.append((i, pkg_len, data[i:i+pkg_len]))
                i += pkg_len
                continue
        i += 1
    return packages

def parse_ifr(data, base_offset=0):
    """Parse IFR opcodes and find suppression conditions."""
    results = []
    i = 0
    while i < len(data):
        if i + 1 >= len(data):
            break
        opcode = data[i]
        length = data[i+1]
        if length == 0 or i + length > len(data):
            i += 1
            continue

        scope = (opcode & 0x80) != 0
        op = opcode & 0x7F

        if op == OP_SUPPRESS_IF:
            # SuppressIf: opcode(1) + length(1) + reserved(1) + condition...
            if length >= 3:
                results.append({
                    'offset': base_offset + i,
                    'type': 'SuppressIf',
                    'opcode': opcode,
                    'length': length,
                    'raw': data[i:i+length],
                    'scope': scope
                })
        elif op == OP_GRAY_OUT_IF:
            if length >= 3:
                results.append({
                    'offset': base_offset + i,
                    'type': 'GrayOutIf',
                    'opcode': opcode,
                    'length': length,
                    'raw': data[i:i+length],
                    'scope': scope
                })
        elif op == OP_DISABLE_IF:
            if length >= 3:
                results.append({
                    'offset': base_offset + i,
                    'type': 'DisableIf',
                    'opcode': opcode,
                    'length': length,
                    'raw': data[i:i+length],
                    'scope': scope
                })
        elif op == OP_FORM:
            if length >= 4:
                form_id = struct.unpack('<H', data[i+2:i+4])[0]
                results.append({
                    'offset': base_offset + i,
                    'type': 'Form',
                    'form_id': form_id,
                    'length': length,
                    'raw': data[i:i+length]
                })
        elif op == OP_REF:
            if length >= 4:
                ref_form = struct.unpack('<H', data[i+2:i+4])[0]
                results.append({
                    'offset': base_offset + i,
                    'type': 'Ref',
                    'ref_form': ref_form,
                    'length': length,
                    'raw': data[i:i+length]
                })

        i += length
    return results

def find_patterns_in_rom(rom_path):
    """Search the full ROM for IFR-related patterns."""
    data = read_file(rom_path)
    print(f"ROM size: {len(data)} bytes")

    # Find all SuppressIf, GrayOutIf, DisableIf in the ROM
    suppress_offsets = []
    gray_offsets = []
    disable_offsets = []

    for i in range(len(data) - 2):
        op = data[i] & 0x7F
        length = data[i+1]
        if length == 0 or length > 64:
            continue

        if op == OP_SUPPRESS_IF and length >= 3:
            suppress_offsets.append(i)
        elif op == OP_GRAY_OUT_IF and length >= 3:
            gray_offsets.append(i)
        elif op == OP_DISABLE_IF and length >= 3:
            disable_offsets.append(i)

    print(f"SuppressIf count: {len(suppress_offsets)}")
    print(f"GrayOutIf count: {len(gray_offsets)}")
    print(f"DisableIf count: {len(disable_offsets)}")

    return data, suppress_offsets, gray_offsets, disable_offsets

def analyze_conditions(data, offsets, cond_type):
    """Analyze what conditions are used in SuppressIf/GrayOutIf/DisableIf."""
    conditions = []
    for off in offsets:
        if off + 2 >= len(data):
            continue
        length = data[off+1]
        if length < 3 or off + length > len(data):
            continue

        # The condition starts after opcode+length+reserved
        # For SuppressIf: opcode(1) + length(1) + reserved(1) = condition starts at off+3
        cond_start = off + 3
        cond_bytes = data[cond_start:off+length]

        # Try to identify simple patterns
        pattern_desc = describe_condition(cond_bytes)
        conditions.append({
            'rom_offset': off,
            'length': length,
            'cond_bytes': cond_bytes.hex(),
            'description': pattern_desc
        })
    return conditions

def describe_condition(cond_bytes):
    """Try to describe the condition in human-readable form."""
    if len(cond_bytes) == 0:
        return "empty"

    parts = []
    i = 0
    while i < len(cond_bytes):
        op = cond_bytes[i] & 0x7F
        scope = (cond_bytes[i] & 0x80) != 0

        if op == OP_TRUE:
            parts.append("TRUE")
            i += 2  # assume 2-byte opcode
        elif op == OP_FALSE:
            parts.append("FALSE")
            i += 2
        elif op == OP_EQ:
            parts.append("EQ")
            i += 2
        elif op == OP_AND:
            parts.append("AND")
            i += 2
        elif op == OP_OR:
            parts.append("OR")
            i += 2
        elif op == OP_NOT:
            parts.append("NOT")
            i += 2
        elif op == OP_ONE:
            parts.append("ONE")
            i += 2
        elif op == OP_ZERO:
            parts.append("ZERO")
            i += 2
        elif op == OP_UINT8:
            if i + 2 < len(cond_bytes):
                parts.append(f"UINT8({cond_bytes[i+2]})")
                i += 3
            else:
                i += 2
        elif op == OP_UINT16:
            if i + 3 < len(cond_bytes):
                parts.append(f"UINT16({struct.unpack('<H', cond_bytes[i+2:i+4])[0]})")
                i += 4
            else:
                i += 2
        elif op == OP_UINT32:
            if i + 5 < len(cond_bytes):
                parts.append(f"UINT32({struct.unpack('<I', cond_bytes[i+2:i+6])[0]})")
                i += 6
            else:
                i += 2
        elif op == OP_QUESTION_REF1:
            if i + 3 < len(cond_bytes):
                parts.append(f"QREF1({struct.unpack('<H', cond_bytes[i+2:i+4])[0]})")
                i += 4
            else:
                i += 2
        elif op == OP_QUESTION_REF2:
            parts.append("QREF2")
            i += 2
        elif op == OP_END_IF:
            parts.append("ENDIF")
            i += 2
        elif op == OP_FORM:
            parts.append("FORM")
            break
        elif op == OP_REF:
            parts.append("REF")
            break
        elif op == 0x5E:  # PUSH opcode in some IFR implementations
            parts.append("PUSH")
            i += 2
        elif op == 0x5F:  # POP
            parts.append("POP")
            i += 2
        else:
            parts.append(f"OP_{op:02X}")
            i += 2

        if scope:
            parts[-1] += "{scope}"

    return " ".join(parts)

def find_access_level_checks(data):
    """Find conditions that check access level (common pattern: eq var 0xXX)."""
    results = []
    for i in range(len(data) - 8):
        # Common pattern for access level check:
        # UINT8 value, QUESTION_REF1/2, EQ, SuppressIf
        # Or: SuppressIf -> EQ -> QREF -> UINT8
        # Look for SuppressIf followed by EQ (0x2F)
        op = data[i] & 0x7F
        if op == OP_SUPPRESS_IF and data[i+1] >= 6:
            next_op = data[i+3] & 0x7F if i+3 < len(data) else 0
            if next_op == OP_EQ:
                results.append({
                    'offset': i,
                    'pattern': 'SuppressIf->EQ',
                    'bytes': data[i:i+12].hex()
                })
    return results

def main():
    rom_path = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"
    setup_pe32 = "/workspace/setup_pe32.bin"

    print("=" * 60)
    print("Analyzing full ROM for IFR suppression conditions...")
    print("=" * 60)
    data, suppress, gray, disable = find_patterns_in_rom(rom_path)

    print("\n--- SuppressIf conditions (first 20) ---")
    conds = analyze_conditions(data, suppress[:20], "SuppressIf")
    for c in conds:
        print(f"  ROM offset 0x{c['rom_offset']:X}: {c['description']}")
        print(f"    raw: {c['cond_bytes']}")

    print("\n--- GrayOutIf conditions (first 20) ---")
    conds = analyze_conditions(data, gray[:20], "GrayOutIf")
    for c in conds:
        print(f"  ROM offset 0x{c['rom_offset']:X}: {c['description']}")
        print(f"    raw: {c['cond_bytes']}")

    print("\n--- DisableIf conditions (first 20) ---")
    conds = analyze_conditions(data, disable[:20], "DisableIf")
    for c in conds:
        print(f"  ROM offset 0x{c['rom_offset']:X}: {c['description']}")
        print(f"    raw: {c['cond_bytes']}")

    # Find access level checks
    print("\n--- Potential access level checks ---")
    access_checks = find_access_level_checks(data)
    for ac in access_checks[:20]:
        print(f"  ROM offset 0x{ac['offset']:X}: {ac['pattern']} bytes={ac['bytes']}")

    # Also analyze Setup PE32 specifically
    print("\n" + "=" * 60)
    print("Analyzing Setup PE32 module...")
    print("=" * 60)
    setup_data = read_file(setup_pe32)
    setup_suppress = [i for i in range(len(setup_data) - 2)
                      if (setup_data[i] & 0x7F) == OP_SUPPRESS_IF and 3 <= setup_data[i+1] <= 64]
    setup_gray = [i for i in range(len(setup_data) - 2)
                  if (setup_data[i] & 0x7F) == OP_GRAY_OUT_IF and 3 <= setup_data[i+1] <= 64]
    setup_disable = [i for i in range(len(setup_data) - 2)
                     if (setup_data[i] & 0x7F) == OP_DISABLE_IF and 3 <= setup_data[i+1] <= 64]

    print(f"Setup PE32 SuppressIf count: {len(setup_suppress)}")
    print(f"Setup PE32 GrayOutIf count: {len(setup_gray)}")
    print(f"Setup PE32 DisableIf count: {len(setup_disable)}")

    print("\n--- Setup SuppressIf conditions (first 30) ---")
    conds = analyze_conditions(setup_data, setup_suppress[:30], "SuppressIf")
    for c in conds:
        print(f"  PE32 offset 0x{c['rom_offset']:X}: {c['description']}")
        print(f"    raw: {c['cond_bytes']}")

    # Save detailed results
    with open('/workspace/ifr_analysis.txt', 'w') as f:
        f.write("IFR Analysis Report\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"ROM: {rom_path}\n")
        f.write(f"ROM size: {len(data)} bytes\n\n")
        f.write(f"Total SuppressIf: {len(suppress)}\n")
        f.write(f"Total GrayOutIf: {len(gray)}\n")
        f.write(f"Total DisableIf: {len(disable)}\n\n")

        f.write("All SuppressIf offsets in ROM:\n")
        for off in suppress:
            f.write(f"  0x{off:08X}\n")

        f.write("\nAll GrayOutIf offsets in ROM:\n")
        for off in gray:
            f.write(f"  0x{off:08X}\n")

        f.write("\nAll DisableIf offsets in ROM:\n")
        for off in disable:
            f.write(f"  0x{off:08X}\n")

    print("\nDetailed analysis saved to /workspace/ifr_analysis.txt")

if __name__ == '__main__':
    main()
