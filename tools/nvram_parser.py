#!/usr/bin/env python3
"""
NVRAM Parser for Lenovo M75s-1 BIOS

Parses AMI NVAR (UEFI Variable) storage format from BIOS ROM images.
Supports extracting, listing, searching, and modifying NVRAM variables.

Usage:
    python nvram_parser.py list <rom_file>
    python nvram_parser.py search <rom_file> <variable_name>
    python nvram_parser.py dump <rom_file> <variable_name> [output_file]
    python nvram_parser.py modify <rom_file> <variable_name> <hex_data>
    python nvram_parser.py info <rom_file>
"""

import argparse
import os
import struct
import sys
import binascii
from typing import List, Optional, Dict, Tuple


class NVARVariable:
    """Represents a single NVAR variable entry."""

    def __init__(self, offset: int, total_size: int, attr: int, state: int,
                 name: str, data: bytes, store_index: int = 0):
        self.offset = offset
        self.total_size = total_size
        self.attr = attr
        self.state = state
        self.name = name
        self.data = data
        self.store_index = store_index

    def __repr__(self):
        return (f"NVARVariable(name='{self.name}', offset=0x{self.offset:x}, "
                f"size={self.total_size}, data_len={len(self.data)})")


class NVRAMStore:
    """Represents an NVRAM store region within the ROM."""

    # Known NVRAM store offsets for Lenovo M75s-1
    KNOWN_STORE_OFFSETS = [0x37090, 0x1037090]
    STORE_SIZE = 0x77F  # 1919 bytes

    def __init__(self, rom_data: bytes, start_offset: int, store_index: int = 0):
        self.rom_data = rom_data
        self.start_offset = start_offset
        self.store_index = store_index
        self.variables: List[NVARVariable] = []
        self._parse_store()

    def _parse_store(self):
        """Parse all NVAR entries within the store region."""
        end_offset = self.start_offset + self.STORE_SIZE
        offset = self.start_offset

        while offset < end_offset - 4:
            if self.rom_data[offset:offset + 4] == b'NVAR':
                var = self._parse_nvar(offset, end_offset)
                if var:
                    self.variables.append(var)
                    # Advance past this entry; do NOT trust total_size for
                    # the first entry if it spans the whole store.
                    if var.total_size > (end_offset - offset) // 2:
                        # Likely a free-space / header entry: scan onward
                        offset += 1
                    else:
                        offset += var.total_size
                    continue
            offset += 1

    def _parse_nvar(self, offset: int, end_offset: int) -> Optional[NVARVariable]:
        """Parse a single NVAR entry at the given offset."""
        if offset + 11 > end_offset:
            return None

        sig = self.rom_data[offset:offset + 4]
        if sig != b'NVAR':
            return None

        total_size = struct.unpack('<H', self.rom_data[offset + 4:offset + 6])[0]
        if total_size == 0 or offset + total_size > end_offset:
            return None

        attr = struct.unpack('<H', self.rom_data[offset + 8:offset + 10])[0]
        state = self.rom_data[offset + 10]

        # Name starts at offset+11, null-terminated
        name_start = offset + 11
        name_end = self.rom_data.find(b'\x00', name_start, offset + total_size)
        if name_end == -1:
            return None

        name = self.rom_data[name_start:name_end].decode('ascii', errors='replace')
        name_len_with_null = name_end - name_start + 1

        header_name_size = 11 + name_len_with_null
        data_size = total_size - header_name_size
        if data_size < 0:
            return None

        var_data = self.rom_data[name_end + 1:offset + total_size]

        return NVARVariable(
            offset=offset,
            total_size=total_size,
            attr=attr,
            state=state,
            name=name,
            data=var_data,
            store_index=self.store_index
        )

    def get_variable(self, name: str) -> Optional[NVARVariable]:
        """Get a variable by name."""
        for var in self.variables:
            if var.name == name:
                return var
        return None

    def find_variables(self, pattern: str) -> List[NVARVariable]:
        """Find variables matching a name pattern (case-insensitive substring)."""
        pattern_lower = pattern.lower()
        return [var for var in self.variables if pattern_lower in var.name.lower()]


class NVRAMParser:
    """Main NVRAM parser for BIOS ROM images."""

    def __init__(self, rom_path: str):
        self.rom_path = rom_path
        with open(rom_path, 'rb') as f:
            self.rom_data = f.read()
        self.stores: List[NVRAMStore] = []
        self._detect_stores()

    def _detect_stores(self):
        """Detect NVRAM stores in the ROM."""
        for i, offset in enumerate(NVRAMStore.KNOWN_STORE_OFFSETS):
            if offset < len(self.rom_data):
                # Verify store signature
                if self.rom_data[offset:offset + 4] == b'NVAR':
                    store = NVRAMStore(self.rom_data, offset, store_index=i)
                    if store.variables:
                        self.stores.append(store)

    def get_all_variables(self) -> List[NVARVariable]:
        """Get all variables from all stores."""
        variables = []
        for store in self.stores:
            variables.extend(store.variables)
        return variables

    def get_variable(self, name: str) -> Optional[NVARVariable]:
        """Get a variable by name from any store."""
        for store in self.stores:
            var = store.get_variable(name)
            if var:
                return var
        return None

    def find_variables(self, pattern: str) -> List[NVARVariable]:
        """Find variables matching a name pattern."""
        results = []
        for store in self.stores:
            results.extend(store.find_variables(pattern))
        return results

    def modify_variable(self, name: str, new_data: bytes, output_path: Optional[str] = None) -> str:
        """
        Modify a variable's data in both NVRAM stores.
        Returns the path to the modified ROM file.
        """
        if output_path is None:
            base, ext = os.path.splitext(self.rom_path)
            output_path = f"{base}_modified{ext}"

        # Create a mutable copy of ROM data
        rom_data = bytearray(self.rom_data)
        modified = False

        for store in self.stores:
            var = store.get_variable(name)
            if var is None:
                continue

            if len(new_data) > len(var.data):
                raise ValueError(
                    f"New data ({len(new_data)} bytes) exceeds variable data size ({len(var.data)} bytes)"
                )

            # Calculate data offset within the ROM
            data_offset = var.offset + 11 + len(var.name) + 1  # header + name + null

            # Pad with original data if new data is shorter (preserve trailing bytes)
            if len(new_data) < len(var.data):
                padded_data = new_data + var.data[len(new_data):]
            else:
                padded_data = new_data

            # Write new data
            rom_data[data_offset:data_offset + len(var.data)] = padded_data
            modified = True

        if not modified:
            raise ValueError(f"Variable '{name}' not found in any store")

        with open(output_path, 'wb') as f:
            f.write(rom_data)

        return output_path

    def get_store_info(self) -> List[Dict]:
        """Get information about all detected stores."""
        info = []
        for store in self.stores:
            info.append({
                'index': store.store_index,
                'start_offset': store.start_offset,
                'end_offset': store.start_offset + NVRAMStore.STORE_SIZE,
                'size': NVRAMStore.STORE_SIZE,
                'variable_count': len(store.variables)
            })
        return info


def format_hex(data: bytes, max_len: int = 64) -> str:
    """Format bytes as hex string, truncating if too long."""
    if len(data) <= max_len:
        return data.hex()
    return data[:max_len].hex() + f"... ({len(data)} bytes total)"


def cmd_list(args):
    """List all NVRAM variables."""
    parser = NVRAMParser(args.rom_file)
    variables = parser.get_all_variables()

    if not variables:
        print("No NVRAM variables found.")
        return

    print(f"{'Store':<6} {'Offset':<12} {'Size':<8} {'Data':<8} {'Name'}")
    print("-" * 60)
    for var in variables:
        store_idx = var.store_index
        offset = f"0x{var.offset:08x}"
        size = var.total_size
        data_len = len(var.data)
        print(f"{store_idx:<6} {offset:<12} {size:<8} {data_len:<8} {var.name}")


def cmd_search(args):
    """Search for variables by name pattern."""
    parser = NVRAMParser(args.rom_file)
    results = parser.find_variables(args.pattern)

    if not results:
        print(f"No variables matching '{args.pattern}' found.")
        return

    print(f"Found {len(results)} variable(s) matching '{args.pattern}':")
    print()
    for var in results:
        print(f"Store:     {var.store_index}")
        print(f"Offset:    0x{var.offset:08x}")
        print(f"Name:      {var.name}")
        print(f"Size:      {var.total_size} bytes")
        print(f"Data Len:  {len(var.data)} bytes")
        print(f"Attr:      0x{var.attr:04x}")
        print(f"State:     0x{var.state:02x}")
        print(f"Data:      {format_hex(var.data)}")
        print("-" * 60)


def cmd_dump(args):
    """Dump a variable's data to file or stdout."""
    parser = NVRAMParser(args.rom_file)
    var = parser.get_variable(args.variable_name)

    if not var:
        print(f"Variable '{args.variable_name}' not found.")
        sys.exit(1)

    if args.output_file:
        with open(args.output_file, 'wb') as f:
            f.write(var.data)
        print(f"Dumped {len(var.data)} bytes to {args.output_file}")
    else:
        print(f"Variable: {var.name}")
        print(f"Offset:   0x{var.offset:08x}")
        print(f"Size:     {var.total_size} bytes")
        print(f"Data:     {len(var.data)} bytes")
        print(f"Attr:     0x{var.attr:04x}")
        print(f"State:    0x{var.state:02x}")
        print()
        print("Hex dump:")
        for i in range(0, len(var.data), 16):
            chunk = var.data[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  0x{i:04x}:  {hex_part:<48}  {ascii_part}")


def cmd_modify(args):
    """Modify a variable's data."""
    parser = NVRAMParser(args.rom_file)

    try:
        new_data = binascii.unhexlify(args.hex_data)
    except binascii.Error as e:
        print(f"Invalid hex data: {e}")
        sys.exit(1)

    try:
        output_path = parser.modify_variable(args.variable_name, new_data, args.output)
        print(f"Modified variable '{args.variable_name}'")
        print(f"New data: {format_hex(new_data)}")
        print(f"Output saved to: {output_path}")
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)


def cmd_info(args):
    """Show NVRAM store information."""
    parser = NVRAMParser(args.rom_file)

    print(f"ROM File:   {args.rom_file}")
    print(f"ROM Size:   {len(parser.rom_data)} bytes ({len(parser.rom_data) // 1024} KiB)")
    print(f"Stores:     {len(parser.stores)}")
    print()

    for info in parser.get_store_info():
        print(f"Store {info['index']}:")
        print(f"  Start:     0x{info['start_offset']:08x}")
        print(f"  End:       0x{info['end_offset']:08x}")
        print(f"  Size:      {info['size']} bytes")
        print(f"  Variables: {info['variable_count']}")
        print()

    variables = parser.get_all_variables()
    if variables:
        print("Variables:")
        for var in variables:
            print(f"  [{var.store_index}] 0x{var.offset:08x} {var.name:<20} ({len(var.data)} bytes)")


def main():
    parser = argparse.ArgumentParser(
        description="NVRAM Parser for Lenovo M75s-1 BIOS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s list IMAGEM2C.ROM
  %(prog)s search IMAGEM2C.ROM Setup
  %(prog)s dump IMAGEM2C.ROM Setup setup.bin
  %(prog)s modify IMAGEM2C.ROM Setup 01020304 --output modified.ROM
  %(prog)s info IMAGEM2C.ROM
        """
    )
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # list command
    list_parser = subparsers.add_parser('list', help='List all NVRAM variables')
    list_parser.add_argument('rom_file', help='Path to BIOS ROM file')

    # search command
    search_parser = subparsers.add_parser('search', help='Search for variables by name')
    search_parser.add_argument('rom_file', help='Path to BIOS ROM file')
    search_parser.add_argument('pattern', help='Name pattern to search for')

    # dump command
    dump_parser = subparsers.add_parser('dump', help='Dump variable data')
    dump_parser.add_argument('rom_file', help='Path to BIOS ROM file')
    dump_parser.add_argument('variable_name', help='Variable name to dump')
    dump_parser.add_argument('output_file', nargs='?', help='Output file (optional)')

    # modify command
    modify_parser = subparsers.add_parser('modify', help='Modify variable data')
    modify_parser.add_argument('rom_file', help='Path to BIOS ROM file')
    modify_parser.add_argument('variable_name', help='Variable name to modify')
    modify_parser.add_argument('hex_data', help='New data as hex string')
    modify_parser.add_argument('--output', '-o', help='Output ROM file path')

    # info command
    info_parser = subparsers.add_parser('info', help='Show NVRAM store information')
    info_parser.add_argument('rom_file', help='Path to BIOS ROM file')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if not os.path.exists(args.rom_file):
        print(f"Error: File not found: {args.rom_file}")
        sys.exit(1)

    commands = {
        'list': cmd_list,
        'search': cmd_search,
        'dump': cmd_dump,
        'modify': cmd_modify,
        'info': cmd_info,
    }

    commands[args.command](args)


if __name__ == '__main__':
    main()
