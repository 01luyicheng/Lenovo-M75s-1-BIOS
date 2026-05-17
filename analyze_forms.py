#!/usr/bin/env python3
"""
Analyze the main form package for SuppressIf/GrayOutIf/DisableIf conditions.
Focus on the large form package in the main DXE volume.
"""

import struct
import os

# IFR opcodes with fixed lengths
FIXED_LEN_OPS = {
    0x00: 2, 0x01: 2, 0x02: 2, 0x03: 2, 0x04: 2,
    0x13: 2, 0x14: 2, 0x15: 2, 0x16: 2, 0x17: 2,
    0x18: 2, 0x19: 2, 0x1A: 2, 0x1B: 2, 0x1C: 2, 0x1D: 2,
    0x1E: 2, 0x1F: 2, 0x20: 2, 0x21: 2, 0x22: 2,
    0x23: 2, 0x24: 2, 0x25: 2, 0x26: 2, 0x27: 2,
    0x29: 2, 0x2A: 2, 0x2B: 2, 0x31: 2, 0x33: 2,
    0x37: 2, 0x39: 2, 0x50: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2,
    0x5A: 3, 0x5B: 4, 0x5C: 6, 0x5D: 10, 0x5E: 4, 0x5F: 2,
}

for i in range(0x60, 0x100):
    FIXED_LEN_OPS[i] = 2  # All question refs are 2 bytes

def parse_ifr(data, base_offset=0):
    """Parse IFR opcodes from a byte stream."""
    results = []
    i = 0
    while i < len(data):
        if i + 1 >= len(data):
            break
        opcode = data[i]
        scope = (opcode & 0x80) != 0
        op = opcode & 0x7F

        if op in FIXED_LEN_OPS:
            length = FIXED_LEN_OPS[op]
            if i + length > len(data):
                break
            results.append({
                'offset': base_offset + i,
                'opcode': op,
                'scope': scope,
                'length': length,
                'raw': data[i:i+length]
            })
            i += length
        else:
            if i + 1 >= len(data):
                break
            length = data[i+1]
            if length == 0 or i + length > len(data):
                i += 1
                continue
            results.append({
                'offset': base_offset + i,
                'opcode': op,
                'scope': scope,
                'length': length,
                'raw': data[i:i+length]
            })
            i += length
    return results

def get_op_name(op):
    names = {
        0x00: "FALSE", 0x01: "TRUE", 0x02: "ONE", 0x03: "ONES", 0x04: "ZERO",
        0x05: "ONE_OF", 0x06: "CHECKBOX", 0x07: "NUMERIC", 0x08: "PASSWORD",
        0x09: "ONE_OF_OPTION", 0x0A: "SUPPRESS_IF", 0x0B: "GRAY_OUT_IF",
        0x0C: "DATE", 0x0D: "TIME", 0x0E: "STRING", 0x0F: "SUBTITLE",
        0x10: "RESET_BUTTON", 0x11: "REF", 0x12: "ACTION", 0x13: "END_FORM",
        0x14: "END_ONE_OF", 0x15: "AND", 0x16: "OR", 0x17: "NOT",
        0x18: "EQUAL", 0x19: "NOT_EQUAL", 0x1A: "GREATER_THAN",
        0x1B: "GREATER_EQUAL", 0x1C: "LESS_THAN", 0x1D: "LESS_EQUAL",
        0x1E: "BITWISE_AND", 0x1F: "BITWISE_OR", 0x20: "BITWISE_NOT",
        0x21: "SHIFT_LEFT", 0x22: "SHIFT_RIGHT", 0x23: "ADD", 0x24: "SUBTRACT",
        0x25: "MULTIPLY", 0x26: "DIVIDE", 0x27: "MODULO",
        0x28: "RULE", 0x29: "END_RULE", 0x2A: "TO_UPPER", 0x2B: "TO_LOWER",
        0x2C: "ORDERED_LIST", 0x2D: "VARSTORE", 0x2E: "VARSTORE_NAME_VALUE",
        0x2F: "VARSTORE_EFI", 0x30: "VARSTORE_DEVICE", 0x31: "END_VARSTORE",
        0x32: "FORM_SET", 0x33: "END_FORM_SET", 0x34: "RULE_REF",
        0x35: "STRING_REF1", 0x36: "STRING_REF2", 0x37: "THIS",
        0x38: "SECURITY", 0x39: "END_IF", 0x3A: "INCONSISTENT_IF",
        0x3B: "NO_SUBMIT_IF", 0x3C: "INFORMATION", 0x3D: "MAP",
        0x3E: "MODAL_TAG", 0x3F: "REF2",
        0x50: "DUP", 0x51: "EQ_ID_VAL", 0x52: "EQ_ID_ID", 0x53: "EQ_ID_VAL_LIST",
        0x5A: "UINT8", 0x5B: "UINT16", 0x5C: "UINT32", 0x5D: "UINT64",
        0x5E: "QUESTION_REF1",
    }
    return names.get(op, f"OP_{op:02X}")

def describe_condition(cond_bytes):
    """Describe condition bytes in a readable form."""
    parts = []
    i = 0
    while i < len(cond_bytes):
        op = cond_bytes[i] & 0x7F
        scope = (cond_bytes[i] & 0x80) != 0
        name = get_op_name(op)

        if op in FIXED_LEN_OPS:
            length = FIXED_LEN_OPS[op]
            if i + length > len(cond_bytes):
                parts.append(f"{name}[truncated]")
                break
            val = ""
            if op == 0x5A and i + 2 < len(cond_bytes):
                val = f"({cond_bytes[i+2]})"
            elif op == 0x5B and i + 3 < len(cond_bytes):
                val = f"({struct.unpack('<H', cond_bytes[i+2:i+4])[0]})"
            elif op == 0x5C and i + 5 < len(cond_bytes):
                val = f"({struct.unpack('<I', cond_bytes[i+2:i+6])[0]})"
            elif op == 0x5E and i + 3 < len(cond_bytes):
                val = f"({struct.unpack('<H', cond_bytes[i+2:i+4])[0]:04X})"
            parts.append(f"{name}{val}")
            i += length
        elif i + 1 < len(cond_bytes):
            length = cond_bytes[i+1]
            if length == 0 or length > 64:
                parts.append(f"{name}[bad_len]")
                i += 2
                continue
            parts.append(f"{name}")
            i += length if length > 0 else 2
        else:
            parts.append(f"{name}[trunc]")
            i += 1
    return " ".join(parts)

def analyze_form_package(data, pkg_offset, pkg_size, rom_base=0):
    """Analyze a single form package for suppression conditions."""
    pkg_data = data[pkg_offset:pkg_offset+pkg_size]
    opcodes = parse_ifr(pkg_data, rom_base + pkg_offset)

    suppress = []
    gray = []
    disable = []
    forms = []

    for op in opcodes:
        if op['opcode'] == 0x0A:
            cond = op['raw'][3:] if len(op['raw']) > 3 else b''
            suppress.append({
                'offset': op['offset'],
                'length': op['length'],
                'cond': cond,
                'desc': describe_condition(cond)
            })
        elif op['opcode'] == 0x0B:
            cond = op['raw'][3:] if len(op['raw']) > 3 else b''
            gray.append({
                'offset': op['offset'],
                'length': op['length'],
                'cond': cond,
                'desc': describe_condition(cond)
            })
        elif op['opcode'] == 0x1C:
            cond = op['raw'][3:] if len(op['raw']) > 3 else b''
            disable.append({
                'offset': op['offset'],
                'length': op['length'],
                'cond': cond,
                'desc': describe_condition(cond)
            })
        elif op['opcode'] == 0x32:  # FORM_SET
            if len(op['raw']) >= 16:
                guid = op['raw'][4:20]
                forms.append({
                    'offset': op['offset'],
                    'type': 'FORM_SET',
                    'guid': guid
                })

    return suppress, gray, disable, forms

def find_form_packages(data, base_offset=0):
    """Find HII form packages."""
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

def main():
    # Analyze the main DXE volume body
    main_body = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom.dump/28 4F1C52D3-D824-4D2A-A2F0-EC40C23C5916/13 9E21FD93-9C72-4C15-8C4B-E77F1DB2D792/0 EE4E5898-3914-4259-9D6E-DC7BD79403CF/1 Volume image section/0 5C60F367-A505-419A-859E-2A4FF6CA6FE5/body.bin"

    with open(main_body, 'rb') as f:
        data = f.read()

    print(f"Main DXE volume size: {len(data)} bytes")

    # Find form packages
    pkgs = find_form_packages(data)
    print(f"Found {len(pkgs)} form packages\n")

    all_suppress = []
    all_gray = []
    all_disable = []

    for idx, (off, size) in enumerate(pkgs):
        print(f"Package {idx}: offset=0x{off:X}, size={size}")
        s, g, d, forms = analyze_form_package(data, off, size)
        print(f"  Forms: {len(forms)}, SuppressIf: {len(s)}, GrayOutIf: {len(g)}, DisableIf: {len(d)}")

        all_suppress.extend(s)
        all_gray.extend(g)
        all_disable.extend(d)

        # Print first few of each for this package
        for item in s[:5]:
            print(f"    SuppressIf @ 0x{item['offset']:X}: {item['desc']}")
            print(f"      raw={item['cond'].hex()}")
        for item in g[:5]:
            print(f"    GrayOutIf @ 0x{item['offset']:X}: {item['desc']}")
            print(f"      raw={item['cond'].hex()}")
        for item in d[:5]:
            print(f"    DisableIf @ 0x{item['offset']:X}: {item['desc']}")
            print(f"      raw={item['cond'].hex()}")
        print()

    print("=" * 70)
    print(f"TOTAL: SuppressIf={len(all_suppress)}, GrayOutIf={len(all_gray)}, DisableIf={len(all_disable)}")
    print("=" * 70)

    # Look for specific patterns that control menu visibility
    print("\n--- Looking for menu visibility control patterns ---")

    # Common patterns:
    # 1. SuppressIf with TRUE condition (always suppress - but we want to find what controls it)
    # 2. SuppressIf with FALSE condition (never suppress - this is what we want to change TO)
    # 3. SuppressIf checking a specific question/value

    # Look for SuppressIf conditions that are NOT just TRUE/FALSE
    interesting = []
    for s in all_suppress:
        if s['cond'] and len(s['cond']) > 2:
            # Not a simple TRUE/FALSE
            interesting.append(s)

    print(f"Found {len(interesting)} SuppressIf with non-trivial conditions")
    for item in interesting[:30]:
        print(f"  0x{item['offset']:X}: {item['desc']}")
        print(f"    raw={item['cond'].hex()}")

    # Look for patterns like: QUESTION_REF1 + UINT8 + EQUAL (checking a var against a value)
    access_checks = []
    for s in all_suppress:
        cond = s['cond']
        if len(cond) >= 6:
            # Pattern: UINT8(value) QUESTION_REF1(qid) EQUAL
            # or: QUESTION_REF1(qid) UINT8(value) EQUAL
            has_qref = 0x5E in cond
            has_uint8 = 0x5A in cond
            has_eq = 0x18 in cond
            if has_qref and has_uint8 and has_eq:
                access_checks.append(s)

    print(f"\nFound {len(access_checks)} SuppressIf with QREF+UINT8+EQUAL pattern")
    for item in access_checks[:30]:
        print(f"  0x{item['offset']:X}: {item['desc']}")
        print(f"    raw={item['cond'].hex()}")

    # Save detailed results
    with open('/workspace/form_analysis.txt', 'w') as f:
        f.write("Form Package Analysis\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"File: {main_body}\n")
        f.write(f"Size: {len(data)} bytes\n")
        f.write(f"Packages: {len(pkgs)}\n\n")
        f.write(f"Total SuppressIf: {len(all_suppress)}\n")
        f.write(f"Total GrayOutIf: {len(all_gray)}\n")
        f.write(f"Total DisableIf: {len(all_disable)}\n\n")

        f.write("All SuppressIf conditions:\n")
        for item in all_suppress:
            f.write(f"  0x{item['offset']:08X}: len={item['length']} desc={item['desc']} raw={item['cond'].hex()}\n")

        f.write("\nAll GrayOutIf conditions:\n")
        for item in all_gray:
            f.write(f"  0x{item['offset']:08X}: len={item['length']} desc={item['desc']} raw={item['cond'].hex()}\n")

        f.write("\nAll DisableIf conditions:\n")
        for item in all_disable:
            f.write(f"  0x{item['offset']:08X}: len={item['length']} desc={item['desc']} raw={item['cond'].hex()}\n")

    print("\nDetailed analysis saved to /workspace/form_analysis.txt")

if __name__ == '__main__':
    main()
