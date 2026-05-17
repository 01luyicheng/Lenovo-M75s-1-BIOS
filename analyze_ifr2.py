#!/usr/bin/env python3
"""
Improved IFR analyzer that properly parses IFR opcodes.
UEFI IFR uses a specific encoding where each opcode has a known length.
"""

import struct
import os

# IFR Opcode definitions (UEFI spec)
IFR_OPS = {
    0x00: ("FALSE", 2),
    0x01: ("TRUE", 2),
    0x02: ("ONE", 2),
    0x03: ("ONES", 2),
    0x04: ("ZERO", 2),
    0x05: ("ONE_OF", None),  # variable
    0x06: ("CHECKBOX", None),
    0x07: ("NUMERIC", None),
    0x08: ("PASSWORD", None),
    0x09: ("ONE_OF_OPTION", None),
    0x0A: ("SUPPRESS_IF", None),  # 3 + condition
    0x0B: ("GRAY_OUT_IF", None),  # 3 + condition
    0x0C: ("DATE", None),
    0x0D: ("TIME", None),
    0x0E: ("STRING", None),
    0x0F: ("SUBTITLE", None),
    0x10: ("RESET_BUTTON", None),
    0x11: ("REF", None),
    0x12: ("ACTION", None),
    0x13: ("END_FORM", 2),
    0x14: ("END_ONE_OF", 2),
    0x15: ("AND", 2),
    0x16: ("OR", 2),
    0x17: ("NOT", 2),
    0x18: ("EQUAL", 2),
    0x19: ("NOT_EQUAL", 2),
    0x1A: ("GREATER_THAN", 2),
    0x1B: ("GREATER_EQUAL", 2),
    0x1C: ("LESS_THAN", 2),
    0x1D: ("LESS_EQUAL", 2),
    0x1E: ("BITWISE_AND", 2),
    0x1F: ("BITWISE_OR", 2),
    0x20: ("BITWISE_NOT", 2),
    0x21: ("SHIFT_LEFT", 2),
    0x22: ("SHIFT_RIGHT", 2),
    0x23: ("ADD", 2),
    0x24: ("SUBTRACT", 2),
    0x25: ("MULTIPLY", 2),
    0x26: ("DIVIDE", 2),
    0x27: ("MODULO", 2),
    0x28: ("RULE", None),
    0x29: ("END_RULE", 2),
    0x2A: ("TO_UPPER", 2),
    0x2B: ("TO_LOWER", 2),
    0x2C: ("ORDERED_LIST", None),
    0x2D: ("VARSTORE", None),
    0x2E: ("VARSTORE_NAME_VALUE", None),
    0x2F: ("VARSTORE_EFI", None),
    0x30: ("VARSTORE_DEVICE", None),
    0x31: ("END_VARSTORE", 2),
    0x32: ("FORM_SET", None),
    0x33: ("END_FORM_SET", 2),
    0x34: ("RULE_REF", None),
    0x35: ("STRING_REF1", None),
    0x36: ("STRING_REF2", None),
    0x37: ("THIS", 2),
    0x38: ("SECURITY", None),
    0x39: ("END_IF", 2),  # ENDIF
    0x3A: ("INCONSISTENT_IF", None),
    0x3B: ("NO_SUBMIT_IF", None),
    0x3C: ("INFORMATION", None),
    0x3D: ("MAP", None),
    0x3E: ("MODAL_TAG", None),
    0x3F: ("REF2", None),
    0x40: ("REF3", None),
    0x41: ("REF4", None),
    0x42: ("REF5", None),
    0x43: ("REF6", None),
    0x44: ("REF7", None),
    0x45: ("REF8", None),
    0x46: ("REF9", None),
    0x47: ("REF10", None),
    0x48: ("REF11", None),
    0x49: ("REF12", None),
    0x4A: ("REF13", None),
    0x4B: ("REF14", None),
    0x4C: ("REF15", None),
    0x4D: ("REF16", None),
    0x4E: ("REF17", None),
    0x4F: ("REF18", None),
    0x50: ("DUP", 2),
    0x51: ("EQ_ID_VAL", None),
    0x52: ("EQ_ID_ID", None),
    0x53: ("EQ_ID_VAL_LIST", None),
    0x54: ("AND", 2),
    0x55: ("OR", 2),
    0x56: ("NOT", 2),
    0x57: ("RULE_CLOSE", 2),
    0x58: ("PUSH", None),
    0x59: ("POP", None),
    0x5A: ("UINT8", 3),     # opcode + length + 1 byte value
    0x5B: ("UINT16", 4),    # opcode + length + 2 byte value
    0x5C: ("UINT32", 6),    # opcode + length + 4 byte value
    0x5D: ("UINT64", 10),   # opcode + length + 8 byte value
    0x5E: ("QUESTION_REF1", 4),  # opcode + length + 2 byte question id
    0x5F: ("QUESTION_REF2", 2),
    0x60: ("QUESTION_REF3", None),
    0x61: ("QUESTION_REF4", None),
    0x62: ("QUESTION_REF5", None),
    0x63: ("QUESTION_REF6", None),
    0x64: ("QUESTION_REF7", None),
    0x65: ("QUESTION_REF8", None),
    0x66: ("QUESTION_REF9", None),
    0x67: ("QUESTION_REF10", None),
    0x68: ("QUESTION_REF11", None),
    0x69: ("QUESTION_REF12", None),
    0x6A: ("QUESTION_REF13", None),
    0x6B: ("QUESTION_REF14", None),
    0x6C: ("QUESTION_REF15", None),
    0x6D: ("QUESTION_REF16", None),
    0x6E: ("QUESTION_REF17", None),
    0x6F: ("QUESTION_REF18", None),
    0x70: ("QUESTION_REF19", None),
    0x71: ("QUESTION_REF20", None),
    0x72: ("QUESTION_REF21", None),
    0x73: ("QUESTION_REF22", None),
    0x74: ("QUESTION_REF23", None),
    0x75: ("QUESTION_REF24", None),
    0x76: ("QUESTION_REF25", None),
    0x77: ("QUESTION_REF26", None),
    0x78: ("QUESTION_REF27", None),
    0x79: ("QUESTION_REF28", None),
    0x7A: ("QUESTION_REF29", None),
    0x7B: ("QUESTION_REF30", None),
    0x7C: ("QUESTION_REF31", None),
    0x7D: ("QUESTION_REF32", None),
    0x7E: ("QUESTION_REF33", None),
    0x7F: ("QUESTION_REF34", None),
    0x80: ("QUESTION_REF35", None),
    0x81: ("QUESTION_REF36", None),
    0x82: ("QUESTION_REF37", None),
    0x83: ("QUESTION_REF38", None),
    0x84: ("QUESTION_REF39", None),
    0x85: ("QUESTION_REF40", None),
    0x86: ("QUESTION_REF41", None),
    0x87: ("QUESTION_REF42", None),
    0x88: ("QUESTION_REF43", None),
    0x89: ("QUESTION_REF44", None),
    0x8A: ("QUESTION_REF45", None),
    0x8B: ("QUESTION_REF46", None),
    0x8C: ("QUESTION_REF47", None),
    0x8D: ("QUESTION_REF48", None),
    0x8E: ("QUESTION_REF49", None),
    0x8F: ("QUESTION_REF50", None),
    0x90: ("QUESTION_REF51", None),
    0x91: ("QUESTION_REF52", None),
    0x92: ("QUESTION_REF53", None),
    0x93: ("QUESTION_REF54", None),
    0x94: ("QUESTION_REF55", None),
    0x95: ("QUESTION_REF56", None),
    0x96: ("QUESTION_REF57", None),
    0x97: ("QUESTION_REF58", None),
    0x98: ("QUESTION_REF59", None),
    0x99: ("QUESTION_REF60", None),
    0x9A: ("QUESTION_REF61", None),
    0x9B: ("QUESTION_REF62", None),
    0x9C: ("QUESTION_REF63", None),
    0x9D: ("QUESTION_REF64", None),
    0x9E: ("QUESTION_REF65", None),
    0x9F: ("QUESTION_REF66", None),
    0xA0: ("QUESTION_REF67", None),
    0xA1: ("QUESTION_REF68", None),
    0xA2: ("QUESTION_REF69", None),
    0xA3: ("QUESTION_REF70", None),
    0xA4: ("QUESTION_REF71", None),
    0xA5: ("QUESTION_REF72", None),
    0xA6: ("QUESTION_REF73", None),
    0xA7: ("QUESTION_REF74", None),
    0xA8: ("QUESTION_REF75", None),
    0xA9: ("QUESTION_REF76", None),
    0xAA: ("QUESTION_REF77", None),
    0xAB: ("QUESTION_REF78", None),
    0xAC: ("QUESTION_REF79", None),
    0xAD: ("QUESTION_REF80", None),
    0xAE: ("QUESTION_REF81", None),
    0xAF: ("QUESTION_REF82", None),
    0xB0: ("QUESTION_REF83", None),
    0xB1: ("QUESTION_REF84", None),
    0xB2: ("QUESTION_REF85", None),
    0xB3: ("QUESTION_REF86", None),
    0xB4: ("QUESTION_REF87", None),
    0xB5: ("QUESTION_REF88", None),
    0xB6: ("QUESTION_REF89", None),
    0xB7: ("QUESTION_REF90", None),
    0xB8: ("QUESTION_REF91", None),
    0xB9: ("QUESTION_REF92", None),
    0xBA: ("QUESTION_REF93", None),
    0xBB: ("QUESTION_REF94", None),
    0xBC: ("QUESTION_REF95", None),
    0xBD: ("QUESTION_REF96", None),
    0xBE: ("QUESTION_REF97", None),
    0xBF: ("QUESTION_REF98", None),
    0xC0: ("QUESTION_REF99", None),
    0xC1: ("QUESTION_REF100", None),
    0xC2: ("QUESTION_REF101", None),
    0xC3: ("QUESTION_REF102", None),
    0xC4: ("QUESTION_REF103", None),
    0xC5: ("QUESTION_REF104", None),
    0xC6: ("QUESTION_REF105", None),
    0xC7: ("QUESTION_REF106", None),
    0xC8: ("QUESTION_REF107", None),
    0xC9: ("QUESTION_REF108", None),
    0xCA: ("QUESTION_REF109", None),
    0xCB: ("QUESTION_REF110", None),
    0xCC: ("QUESTION_REF111", None),
    0xCD: ("QUESTION_REF112", None),
    0xCE: ("QUESTION_REF113", None),
    0xCF: ("QUESTION_REF114", None),
    0xD0: ("QUESTION_REF115", None),
    0xD1: ("QUESTION_REF116", None),
    0xD2: ("QUESTION_REF117", None),
    0xD3: ("QUESTION_REF118", None),
    0xD4: ("QUESTION_REF119", None),
    0xD5: ("QUESTION_REF120", None),
    0xD6: ("QUESTION_REF121", None),
    0xD7: ("QUESTION_REF122", None),
    0xD8: ("QUESTION_REF123", None),
    0xD9: ("QUESTION_REF124", None),
    0xDA: ("QUESTION_REF125", None),
    0xDB: ("QUESTION_REF126", None),
    0xDC: ("QUESTION_REF127", None),
    0xDD: ("QUESTION_REF128", None),
    0xDE: ("QUESTION_REF129", None),
    0xDF: ("QUESTION_REF130", None),
    0xE0: ("QUESTION_REF131", None),
    0xE1: ("QUESTION_REF132", None),
    0xE2: ("QUESTION_REF133", None),
    0xE3: ("QUESTION_REF134", None),
    0xE4: ("QUESTION_REF135", None),
    0xE5: ("QUESTION_REF136", None),
    0xE6: ("QUESTION_REF137", None),
    0xE7: ("QUESTION_REF138", None),
    0xE8: ("QUESTION_REF139", None),
    0xE9: ("QUESTION_REF140", None),
    0xEA: ("QUESTION_REF141", None),
    0xEB: ("QUESTION_REF142", None),
    0xEC: ("QUESTION_REF143", None),
    0xED: ("QUESTION_REF144", None),
    0xEE: ("QUESTION_REF145", None),
    0xEF: ("QUESTION_REF146", None),
    0xF0: ("QUESTION_REF147", None),
    0xF1: ("QUESTION_REF148", None),
    0xF2: ("QUESTION_REF149", None),
    0xF3: ("QUESTION_REF150", None),
    0xF4: ("QUESTION_REF151", None),
    0xF5: ("QUESTION_REF152", None),
    0xF6: ("QUESTION_REF153", None),
    0xF7: ("QUESTION_REF154", None),
    0xF8: ("QUESTION_REF155", None),
    0xF9: ("QUESTION_REF156", None),
    0xFA: ("QUESTION_REF157", None),
    0xFB: ("QUESTION_REF158", None),
    0xFC: ("QUESTION_REF159", None),
    0xFD: ("QUESTION_REF160", None),
    0xFE: ("QUESTION_REF161", None),
    0xFF: ("QUESTION_REF162", None),
}

def get_opcode_length(opcode):
    """Get the length of an IFR opcode."""
    op = opcode & 0x7F
    if op in IFR_OPS:
        name, length = IFR_OPS[op]
        return length
    return None

def parse_ifr_stream(data, base_offset=0):
    """Parse IFR opcodes from a byte stream."""
    results = []
    i = 0
    while i < len(data):
        if i + 1 >= len(data):
            break
        opcode = data[i]
        scope = (opcode & 0x80) != 0
        op = opcode & 0x7F

        # For opcodes that have a fixed length
        known_len = get_opcode_length(opcode)
        if known_len is not None:
            length = known_len
            if i + length > len(data):
                break
            results.append({
                'offset': base_offset + i,
                'opcode': op,
                'scope': scope,
                'name': IFR_OPS[op][0],
                'length': length,
                'raw': data[i:i+length]
            })
            i += length
            continue

        # For opcodes with variable length, use the length byte
        if i + 1 >= len(data):
            break
        length = data[i+1]
        if length == 0 or i + length > len(data):
            i += 1
            continue

        name = IFR_OPS.get(op, (f"UNKNOWN_{op:02X}", None))[0]
        results.append({
            'offset': base_offset + i,
            'opcode': op,
            'scope': scope,
            'name': name,
            'length': length,
            'raw': data[i:i+length]
        })
        i += length

    return results

def find_suppress_conditions(data, base_offset=0):
    """Find all SuppressIf/GrayOutIf/DisableIf and their conditions."""
    opcodes = parse_ifr_stream(data, base_offset)

    conditions = []
    i = 0
    while i < len(opcodes):
        op = opcodes[i]
        if op['name'] in ('SUPPRESS_IF', 'GRAY_OUT_IF', 'DISABLE_IF'):
            # The condition is embedded in the opcode's payload
            # For SuppressIf: opcode(1) + length(1) + reserved(1) + condition...
            # The condition ends when we reach the next non-condition opcode
            # or when the length byte indicates the end
            raw = op['raw']
            if len(raw) >= 3:
                cond_bytes = raw[3:]
                conditions.append({
                    'offset': op['offset'],
                    'type': op['name'],
                    'length': op['length'],
                    'cond_bytes': cond_bytes,
                    'raw': raw
                })
        i += 1
    return conditions

def describe_condition_bytes(cond_bytes):
    """Parse condition bytes into a readable string."""
    parts = []
    i = 0
    while i < len(cond_bytes):
        if i >= len(cond_bytes):
            break
        opcode = cond_bytes[i]
        op = opcode & 0x7F
        scope = (opcode & 0x80) != 0

        known_len = get_opcode_length(opcode)
        if known_len is not None:
            name = IFR_OPS.get(op, (f"OP_{op:02X}", None))[0]
            val = ""
            if op == 0x5A and i + 2 < len(cond_bytes):  # UINT8
                val = f"({cond_bytes[i+2]})"
            elif op == 0x5B and i + 3 < len(cond_bytes):  # UINT16
                val = f"({struct.unpack('<H', cond_bytes[i+2:i+4])[0]})"
            elif op == 0x5C and i + 5 < len(cond_bytes):  # UINT32
                val = f"({struct.unpack('<I', cond_bytes[i+2:i+6])[0]})"
            elif op == 0x5E and i + 3 < len(cond_bytes):  # QUESTION_REF1
                val = f"({struct.unpack('<H', cond_bytes[i+2:i+4])[0]})"
            parts.append(f"{name}{val}")
            i += known_len
        elif i + 1 < len(cond_bytes):
            length = cond_bytes[i+1]
            if length == 0 or length > 64:
                parts.append(f"OP_{op:02X}")
                i += 2
                continue
            name = IFR_OPS.get(op, (f"UNKNOWN_{op:02X}", None))[0]
            parts.append(f"{name}")
            i += length if length > 0 else 2
        else:
            parts.append(f"OP_{op:02X}")
            i += 1
    return " ".join(parts)

def find_form_packages(data):
    """Find HII form packages in the data."""
    packages = []
    i = 0
    while i < len(data) - 4:
        # HII package header: type (1 byte), length (3 bytes, little endian)
        pkg_type = data[i]
        pkg_len = struct.unpack('<I', data[i:i+3] + b'\x00')[0] & 0xFFFFFF
        if pkg_type == 0x02 and pkg_len >= 8 and pkg_len < 0x100000 and i + pkg_len <= len(data):
            # Check if it looks like a valid form package
            # After header (4 bytes), should be FORM_SET (0x32) or similar
            first_op = data[i+4] & 0x7F if i+4 < len(data) else 0
            if first_op == 0x32:  # FORM_SET
                packages.append((i, pkg_len))
                i += pkg_len
                continue
        i += 1
    return packages

def main():
    rom_path = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"
    setup_pe32 = "/workspace/setup_pe32.bin"

    print("=" * 70)
    print("IFR Analysis - Looking for form packages and suppression conditions")
    print("=" * 70)

    # Analyze full ROM
    with open(rom_path, 'rb') as f:
        rom_data = f.read()

    print(f"\nROM size: {len(rom_data)} bytes")

    # Find form packages in ROM
    form_pkgs = find_form_packages(rom_data)
    print(f"Found {len(form_pkgs)} form packages in ROM")

    # Analyze Setup PE32
    with open(setup_pe32, 'rb') as f:
        setup_data = f.read()

    print(f"\nSetup PE32 size: {len(setup_data)} bytes")

    setup_pkgs = find_form_packages(setup_data)
    print(f"Found {len(setup_pkgs)} form packages in Setup PE32")

    # Search for suppression conditions in the full ROM
    print("\n" + "=" * 70)
    print("Scanning ROM for SuppressIf/GrayOutIf/DisableIf patterns")
    print("=" * 70)

    # Simple scan: look for SuppressIf (0x0A), GrayOutIf (0x0B), DisableIf (0x1C)
    # with reasonable length bytes
    suppress_offsets = []
    gray_offsets = []
    disable_offsets = []

    for i in range(len(rom_data) - 2):
        op = rom_data[i] & 0x7F
        length = rom_data[i+1]
        if length < 3 or length > 64:
            continue
        if op == 0x0A:
            suppress_offsets.append(i)
        elif op == 0x0B:
            gray_offsets.append(i)
        elif op == 0x1C:
            disable_offsets.append(i)

    print(f"SuppressIf: {len(suppress_offsets)}")
    print(f"GrayOutIf: {len(gray_offsets)}")
    print(f"DisableIf: {len(disable_offsets)}")

    # Focus on Setup PE32
    print("\n" + "=" * 70)
    print("Analyzing Setup PE32 module in detail")
    print("=" * 70)

    setup_suppress = []
    setup_gray = []
    setup_disable = []

    for i in range(len(setup_data) - 2):
        op = setup_data[i] & 0x7F
        length = setup_data[i+1]
        if length < 3 or length > 64:
            continue
        if op == 0x0A:
            setup_suppress.append(i)
        elif op == 0x0B:
            setup_gray.append(i)
        elif op == 0x1C:
            setup_disable.append(i)

    print(f"Setup PE32 SuppressIf: {len(setup_suppress)}")
    print(f"Setup PE32 GrayOutIf: {len(setup_gray)}")
    print(f"Setup PE32 DisableIf: {len(setup_disable)}")

    # Analyze conditions in Setup PE32
    print("\n--- Setup SuppressIf conditions ---")
    for off in setup_suppress[:30]:
        length = setup_data[off+1]
        cond = setup_data[off+3:off+length]
        desc = describe_condition_bytes(cond)
        print(f"  0x{off:05X}: len={length:2d} cond=[{desc}]")
        print(f"           raw={setup_data[off:off+length].hex()}")

    print("\n--- Setup GrayOutIf conditions ---")
    for off in setup_gray[:30]:
        length = setup_data[off+1]
        cond = setup_data[off+3:off+length]
        desc = describe_condition_bytes(cond)
        print(f"  0x{off:05X}: len={length:2d} cond=[{desc}]")
        print(f"           raw={setup_data[off:off+length].hex()}")

    print("\n--- Setup DisableIf conditions ---")
    for off in setup_disable[:30]:
        length = setup_data[off+1]
        cond = setup_data[off+3:off+length]
        desc = describe_condition_bytes(cond)
        print(f"  0x{off:05X}: len={length:2d} cond=[{desc}]")
        print(f"           raw={setup_data[off:off+length].hex()}")

    # Look for access level patterns: common pattern is checking a variable against a value
    # e.g., SuppressIf -> EQ -> QUESTION_REF1 -> UINT8(value)
    print("\n" + "=" * 70)
    print("Looking for access level / menu visibility control patterns")
    print("=" * 70)

    access_patterns = []
    for off in setup_suppress:
        length = setup_data[off+1]
        if length < 6:
            continue
        cond = setup_data[off+3:off+length]
        # Look for EQ (0x18) followed by question ref and value
        if len(cond) >= 4:
            # Check for common patterns
            if cond[0] == 0x18:  # EQUAL
                access_patterns.append({
                    'offset': off,
                    'type': 'SuppressIf->EQUAL',
                    'raw': setup_data[off:off+length].hex()
                })
            elif cond[0] == 0x5E and len(cond) >= 4:  # QUESTION_REF1
                # Check if followed by comparison
                access_patterns.append({
                    'offset': off,
                    'type': 'SuppressIf->QREF1',
                    'raw': setup_data[off:off+length].hex()
                })

    print(f"Found {len(access_patterns)} potential access control patterns in Setup PE32")
    for p in access_patterns[:20]:
        print(f"  0x{p['offset']:05X}: {p['type']} raw={p['raw']}")

    # Save results
    with open('/workspace/ifr_analysis2.txt', 'w') as f:
        f.write("IFR Analysis Report v2\n")
        f.write("=" * 70 + "\n\n")
        f.write(f"ROM: {rom_path}\n")
        f.write(f"Setup PE32: {setup_pe32}\n\n")
        f.write(f"Setup PE32 SuppressIf: {len(setup_suppress)}\n")
        f.write(f"Setup PE32 GrayOutIf: {len(setup_gray)}\n")
        f.write(f"Setup PE32 DisableIf: {len(setup_disable)}\n\n")

        f.write("All Setup PE32 SuppressIf offsets:\n")
        for off in setup_suppress:
            length = setup_data[off+1]
            cond = setup_data[off+3:off+length]
            desc = describe_condition_bytes(cond)
            f.write(f"  0x{off:05X}: len={length:2d} cond=[{desc}] raw={setup_data[off:off+length].hex()}\n")

        f.write("\nAll Setup PE32 GrayOutIf offsets:\n")
        for off in setup_gray:
            length = setup_data[off+1]
            cond = setup_data[off+3:off+length]
            desc = describe_condition_bytes(cond)
            f.write(f"  0x{off:05X}: len={length:2d} cond=[{desc}] raw={setup_data[off:off+length].hex()}\n")

        f.write("\nAll Setup PE32 DisableIf offsets:\n")
        for off in setup_disable:
            length = setup_data[off+1]
            cond = setup_data[off+3:off+length]
            desc = describe_condition_bytes(cond)
            f.write(f"  0x{off:05X}: len={length:2d} cond=[{desc}] raw={setup_data[off:off+length].hex()}\n")

    print("\nDetailed analysis saved to /workspace/ifr_analysis2.txt")

if __name__ == '__main__':
    main()
