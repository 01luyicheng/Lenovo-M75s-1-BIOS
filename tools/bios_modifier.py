#!/usr/bin/env python3
"""BIOS modifier for Lenovo M75s-1 - unlock hidden options and tweak settings.

This module provides a safe, reproducible way to modify BIOS settings in the
32 MiB SPI image (IMAGEM2C.ROM).  All changes are applied to both NVRAM
mirrors (0x00037000 and 0x01037000) so the two copies stay consistent.

Only the Python standard library is used so the tool works in minimal
recovery / research environments.

**WARNING**: Modifying firmware can brick your device.  Always have a
hardware flash programmer (e.g. CH341A) ready for recovery before flashing
any modified image.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import struct
import sys
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import BinaryIO, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants derived from the M75s-1 ROM analysis
# ---------------------------------------------------------------------------

ROM_SIZE_EXPECTED = 33_554_432  # 32 MiB

# NVRAM / variable store mirrors
NVRAM_MIRRORS: Tuple[int, int] = (0x00037000, 0x01037000)

# Setup variable (main BIOS settings)
SETUP_VAR_NAME_POS = 0x370A7          # offset of "Setup\0" in primary mirror
SETUP_DATA_OFFSET = 0x370B8           # start of Setup data payload
SETUP_DATA_LENGTH = 0x20D             # ~525 bytes

# AMITSESetup variable (AMI TSE / UI state)
AMITSE_VAR_NAME_POS = 0x372F8
AMITSE_DATA_OFFSET = 0x3730F
AMITSE_DATA_LENGTH = 0x183            # ~387 bytes

# Offsets relative to the *start of the NVRAM mirror* (0x37000 / 0x1037000)
SETUP_DATA_REL_OFFSET = SETUP_DATA_OFFSET - NVRAM_MIRRORS[0]
AMITSE_DATA_REL_OFFSET = AMITSE_DATA_OFFSET - NVRAM_MIRRORS[0]

# SecureBootSetup, ROM_CMN, PCI_COMMON (for reference / future use)
SECUREBOOT_NAME_POS = 0x375F1
ROM_CMN_NAME_POS = 0x37613
PCI_COMMON_NAME_POS = 0x37722


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class BitWidth(IntEnum):
    """Supported bit-field widths."""
    UINT8 = 8
    UINT16 = 16
    UINT32 = 32


@dataclass(frozen=True)
class BitField:
    """Description of a single bit-field inside a Setup variable."""
    name: str
    description: str
    offset: int          # byte offset inside Setup data
    bit_mask: int        # e.g. 0x01, 0x02, 0x04 … 0xFF
    width: BitWidth = BitWidth.UINT8
    default_value: int = 0
    enabled_value: int = 1
    disabled_value: int = 0
    category: str = "General"
    danger: bool = False  # if True, extra warnings are shown

    @property
    def bit_position(self) -> int:
        """Return the LSB position of the mask (0-7 for UINT8)."""
        if self.bit_mask == 0:
            return 0
        return (self.bit_mask & -self.bit_mask).bit_length() - 1

    def read(self, data: bytes) -> int:
        """Extract the field value from *data*."""
        if self.width == BitWidth.UINT8:
            raw = data[self.offset]
        elif self.width == BitWidth.UINT16:
            raw = struct.unpack_from("<H", data, self.offset)[0]
        elif self.width == BitWidth.UINT32:
            raw = struct.unpack_from("<I", data, self.offset)[0]
        else:
            raise ValueError(f"Unsupported width {self.width}")
        return (raw & self.bit_mask) >> self.bit_position

    def write(self, data: bytearray, value: int) -> None:
        """Set the field to *value* inside mutable *data*."""
        if self.width == BitWidth.UINT8:
            raw = data[self.offset]
            raw = (raw & ~self.bit_mask) | ((value << self.bit_position) & self.bit_mask)
            data[self.offset] = raw
        elif self.width == BitWidth.UINT16:
            raw = struct.unpack_from("<H", data, self.offset)[0]
            raw = (raw & ~self.bit_mask) | ((value << self.bit_position) & self.bit_mask)
            struct.pack_into("<H", data, self.offset, raw)
        elif self.width == BitWidth.UINT32:
            raw = struct.unpack_from("<I", data, self.offset)[0]
            raw = (raw & ~self.bit_mask) | ((value << self.bit_position) & self.bit_mask)
            struct.pack_into("<I", data, self.offset, raw)
        else:
            raise ValueError(f"Unsupported width {self.width}")


@dataclass
class Modification:
    """A requested change: which field and what target value."""
    field: BitField
    target_value: int


# ---------------------------------------------------------------------------
# Known bit-fields (educated guesses based on AMI AM4 platform patterns)
#
# NOTE: These offsets are *relative to the Setup data payload start*.
#       They are derived from common AMI AM4 layouts and the analysis
#       documents.  Always verify with IFRExtractor output before relying
#       on them for production modifications.
# ---------------------------------------------------------------------------

KNOWN_FIELDS: Tuple[BitField, ...] = (
    # ---- Above 4G Decoding / ReBAR prerequisites ----
    BitField(
        name="above_4g_decoding",
        description="Enable 64-bit MMIO Above 4G Decoding (prerequisite for ReBAR)",
        offset=0x00,
        bit_mask=0x01,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    BitField(
        name="sr_iov",
        description="Single Root I/O Virtualization (SR-IOV)",
        offset=0x00,
        bit_mask=0x02,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    BitField(
        name="acs_override",
        description="ACS Override for PCIe passthrough",
        offset=0x00,
        bit_mask=0x04,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    BitField(
        name="large_bar_support",
        description="Large BAR / Resizable BAR support hint",
        offset=0x00,
        bit_mask=0x08,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    # ---- AMD CBS / PBS menu visibility ----
    BitField(
        name="amd_cbs_menu",
        description="Show AMD CBS (Common BIOS Settings) menu",
        offset=0x01,
        bit_mask=0x01,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="AMD CBS / PBS",
    ),
    BitField(
        name="amd_pbs_menu",
        description="Show AMD PBS (Platform BIOS Settings) menu",
        offset=0x01,
        bit_mask=0x02,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="AMD CBS / PBS",
    ),
    BitField(
        name="nbio_menu",
        description="Show NBIO (Northbridge IO) configuration menu",
        offset=0x01,
        bit_mask=0x04,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="AMD CBS / PBS",
    ),
    BitField(
        name="fch_menu",
        description="Show FCH (Fusion Controller Hub) menu",
        offset=0x01,
        bit_mask=0x08,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="AMD CBS / PBS",
    ),
    # ---- PCIe / IOMMU ----
    BitField(
        name="iommu",
        description="Enable IOMMU (AMD-Vi) for device passthrough",
        offset=0x02,
        bit_mask=0x01,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    BitField(
        name="iommu_aggressive",
        description="IOMMU aggressive mode / ATS",
        offset=0x02,
        bit_mask=0x02,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="PCIe / GPU",
    ),
    # ---- CSM / UEFI ----
    BitField(
        name="csm_support",
        description="Compatibility Support Module (CSM) enable",
        offset=0x03,
        bit_mask=0x01,
        default_value=1,
        enabled_value=1,
        disabled_value=0,
        category="Boot",
    ),
    BitField(
        name="secure_boot",
        description="Secure Boot enable",
        offset=0x04,
        bit_mask=0x01,
        default_value=1,
        enabled_value=1,
        disabled_value=0,
        category="Security",
        danger=True,
    ),
    # ---- Memory / XMP (experimental placeholders) ----
    BitField(
        name="memory_profile",
        description="Memory profile / XMP selection (0=Auto, 1=Manual, 2=Profile1)",
        offset=0x05,
        bit_mask=0x03,
        default_value=0,
        enabled_value=2,
        disabled_value=0,
        category="Memory",
    ),
    BitField(
        name="memory_overclock",
        description="Allow memory overclocking",
        offset=0x05,
        bit_mask=0x04,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="Memory",
    ),
    # ---- Advanced / debug ----
    BitField(
        name="debug_mode",
        description="Enable BIOS debug output (serial / ACPI)",
        offset=0x06,
        bit_mask=0x01,
        default_value=0,
        enabled_value=1,
        disabled_value=0,
        category="Advanced",
    ),
    BitField(
        name="svm_mode",
        description="SVM (AMD-V) virtualization enable",
        offset=0x07,
        bit_mask=0x01,
        default_value=1,
        enabled_value=1,
        disabled_value=0,
        category="Advanced",
    ),
)

# Build lookup tables
_FIELD_BY_NAME = {f.name: f for f in KNOWN_FIELDS}
_CATEGORIES = sorted({f.category for f in KNOWN_FIELDS})


# ---------------------------------------------------------------------------
# ROM I/O helpers
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_rom(path: Path) -> bytes:
    """Read the ROM, validate size, and return its contents."""
    if not path.exists():
        raise FileNotFoundError(f"ROM file not found: {path}")
    data = path.read_bytes()
    if len(data) != ROM_SIZE_EXPECTED:
        raise ValueError(
            f"ROM size mismatch: expected {ROM_SIZE_EXPECTED} bytes, got {len(data)}"
        )
    return data


def create_backup(rom_path: Path) -> Path:
    """Create a timestamped backup next to the original file."""
    ts = time.strftime("%Y%m%d_%H%M%S")
    backup_path = rom_path.with_suffix(f".ROM.backup_{ts}")
    if backup_path.exists():
        # Append microsecond if collision happens
        backup_path = rom_path.with_suffix(f".ROM.backup_{ts}_{time.time():.6f}")
    shutil.copy2(rom_path, backup_path)
    return backup_path


# ---------------------------------------------------------------------------
# NVRAM / Setup variable access
# ---------------------------------------------------------------------------

class BiosModifier:
    """High-level interface to read and modify BIOS settings."""

    def __init__(self, rom_data: bytes) -> None:
        if len(rom_data) != ROM_SIZE_EXPECTED:
            raise ValueError("Invalid ROM size")
        self._data = bytearray(rom_data)
        self._validate_mirrors()

    # -- internal validation ------------------------------------------------

    def _validate_mirrors(self) -> None:
        """Ensure both NVRAM mirrors contain the expected variable names."""
        for base in NVRAM_MIRRORS:
            setup_pos = self._data.find(b"Setup\x00", base, base + 0x20000)
            if setup_pos < 0:
                raise ValueError(f"Setup variable not found in mirror at {base:#x}")
            amitse_pos = self._data.find(b"AMITSESetup\x00", base, base + 0x20000)
            if amitse_pos < 0:
                raise ValueError(f"AMITSESetup variable not found in mirror at {base:#x}")

    def _mirror_offsets(self, abs_offset: int) -> Tuple[int, int]:
        """Return the absolute offsets for both NVRAM mirrors."""
        rel = abs_offset - NVRAM_MIRRORS[0]
        return (NVRAM_MIRRORS[0] + rel, NVRAM_MIRRORS[1] + rel)

    # -- raw data access ----------------------------------------------------

    def read_setup_data(self) -> bytes:
        """Return a copy of the Setup data payload (primary mirror)."""
        return bytes(self._data[SETUP_DATA_OFFSET:SETUP_DATA_OFFSET + SETUP_DATA_LENGTH])

    def read_amitse_data(self) -> bytes:
        """Return a copy of the AMITSESetup data payload (primary mirror)."""
        return bytes(self._data[AMITSE_DATA_OFFSET:AMITSE_DATA_OFFSET + AMITSE_DATA_LENGTH])

    def write_setup_data(self, payload: bytes) -> None:
        """Write *payload* to both Setup data mirrors."""
        if len(payload) != SETUP_DATA_LENGTH:
            raise ValueError(
                f"Setup payload length mismatch: expected {SETUP_DATA_LENGTH}, got {len(payload)}"
            )
        for off in self._mirror_offsets(SETUP_DATA_OFFSET):
            self._data[off:off + SETUP_DATA_LENGTH] = payload

    def write_amitse_data(self, payload: bytes) -> None:
        """Write *payload* to both AMITSESetup data mirrors."""
        if len(payload) != AMITSE_DATA_LENGTH:
            raise ValueError(
                f"AMITSE payload length mismatch: expected {AMITSE_DATA_LENGTH}, got {len(payload)}"
            )
        for off in self._mirror_offsets(AMITSE_DATA_OFFSET):
            self._data[off:off + AMITSE_DATA_LENGTH] = payload

    # -- high-level field access --------------------------------------------

    def read_field(self, field: BitField) -> int:
        """Read current value of *field* from Setup data."""
        setup = bytearray(self.read_setup_data())
        return field.read(setup)

    def write_field(self, field: BitField, value: int) -> None:
        """Set *field* to *value* in both Setup mirrors."""
        setup = bytearray(self.read_setup_data())
        field.write(setup, value)
        self.write_setup_data(bytes(setup))

    def apply_modifications(self, modifications: Iterable[Modification]) -> List[Modification]:
        """Apply multiple modifications atomically and return what changed."""
        setup = bytearray(self.read_setup_data())
        applied: List[Modification] = []
        for mod in modifications:
            old = mod.field.read(setup)
            if old != mod.target_value:
                mod.field.write(setup, mod.target_value)
                applied.append(mod)
        if applied:
            self.write_setup_data(bytes(setup))
        return applied

    # -- export --------------------------------------------------------------

    def rom_bytes(self) -> bytes:
        """Return the current (possibly modified) ROM image."""
        return bytes(self._data)

    def diff_summary(self, original: bytes) -> str:
        """Return a human-readable summary of bytes that changed."""
        if len(original) != len(self._data):
            return "[Size mismatch – cannot diff]"
        lines: List[str] = []
        for i, (a, b) in enumerate(zip(original, self._data)):
            if a != b:
                lines.append(f"  {i:#010x}: {a:02x} -> {b:02x}")
                if len(lines) >= 20:
                    lines.append("  ... (truncated)")
                    break
        return "\n".join(lines) if lines else "[No changes]"


# ---------------------------------------------------------------------------
# User interaction
# ---------------------------------------------------------------------------

def ask_yes_no(prompt: str, default: bool = False) -> bool:
    """Ask the user a yes/no question."""
    suffix = " [Y/n]: " if default else " [y/N]: "
    try:
        answer = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if not answer:
        return default
    return answer in ("y", "yes")


def confirm_dangerous(field: BitField) -> bool:
    """Extra confirmation for dangerous modifications."""
    print(f"\n*** WARNING ***")
    print(f"'{field.name}' is marked as DANGEROUS.")
    print(f"Description: {field.description}")
    print("Incorrect values may prevent the system from booting.")
    return ask_yes_no("Do you want to proceed anyway?", default=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_list(_args: argparse.Namespace) -> int:
    """List all known modifiable fields with current values."""
    rom_path = Path(_args.rom)
    try:
        data = validate_rom(rom_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    mod = BiosModifier(data)

    print(f"ROM: {rom_path}")
    print(f"SHA256: {sha256_file(rom_path)}")
    print(f"\nKnown modifiable fields:\n")

    for cat in _CATEGORIES:
        print(f"[{cat}]")
        for field in KNOWN_FIELDS:
            if field.category != cat:
                continue
            current = mod.read_field(field)
            danger_flag = " [!DANGEROUS]" if field.danger else ""
            print(
                f"  {field.name:<25} "
                f"offset={field.offset:#04x} mask={field.bit_mask:#04x} "
                f"current={current}{danger_flag}"
            )
            print(f"      {field.description}")
        print()

    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    """Apply one or more modifications to the ROM."""
    rom_path = Path(args.rom)
    try:
        original_data = validate_rom(rom_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    # Parse requested modifications
    mods: List[Modification] = []
    for token in args.mods:
        # Syntax: field_name=value  or  field_name:on  or  field_name:off
        if "=" in token:
            name, val_str = token.split("=", 1)
            target = int(val_str, 0)
        elif ":" in token:
            name, switch = token.split(":", 1)
            field = _FIELD_BY_NAME.get(name)
            if field is None:
                print(f"Error: unknown field '{name}'", file=sys.stderr)
                return 1
            target = field.enabled_value if switch.lower() in ("on", "1", "yes", "true") else field.disabled_value
        else:
            # Default: toggle to enabled value
            name = token
            field = _FIELD_BY_NAME.get(name)
            if field is None:
                print(f"Error: unknown field '{name}'", file=sys.stderr)
                return 1
            target = field.enabled_value

        field = _FIELD_BY_NAME.get(name)
        if field is None:
            print(f"Error: unknown field '{name}'", file=sys.stderr)
            return 1
        mods.append(Modification(field=field, target_value=target))

    if not mods:
        print("No modifications requested.")
        return 0

    # Show preview
    print(f"ROM: {rom_path}")
    print(f"SHA256 (original): {sha256_file(rom_path)}")
    print(f"\nRequested modifications:\n")
    for mod in mods:
        current = BiosModifier(original_data).read_field(mod.field)
        print(f"  {mod.field.name}")
        print(f"    Current: {current}")
        print(f"    Target:  {mod.target_value}")
        if mod.field.danger and not confirm_dangerous(mod.field):
            print("Aborted.")
            return 130

    if not args.yes:
        if not ask_yes_no("\nApply these modifications?", default=False):
            print("Aborted.")
            return 130

    # Backup
    backup_path = create_backup(rom_path)
    print(f"\nBackup created: {backup_path}")

    # Apply
    modifier = BiosModifier(original_data)
    applied = modifier.apply_modifications(mods)

    if not applied:
        print("No changes were necessary (values already match targets).")
        return 0

    print(f"\nApplied {len(applied)} change(s):")
    for mod in applied:
        print(f"  {mod.field.name} -> {mod.target_value}")

    # Diff preview (first few changed bytes)
    diff = modifier.diff_summary(original_data)
    if diff != "[No changes]":
        print(f"\nRaw diff (first changes):")
        print(diff)

    # Write
    new_data = modifier.rom_bytes()
    rom_path.write_bytes(new_data)
    print(f"\nModified ROM written to: {rom_path}")
    print(f"New SHA256: {sha256_file(rom_path)}")
    print("\n*** IMPORTANT ***")
    print("Verify the backup and have a hardware programmer ready before flashing.")
    return 0


def cmd_dump(args: argparse.Namespace) -> int:
    """Dump raw Setup / AMITSE data payloads to stdout or files."""
    rom_path = Path(args.rom)
    try:
        data = validate_rom(rom_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    modifier = BiosModifier(data)

    if args.setup:
        payload = modifier.read_setup_data()
        if args.output:
            Path(args.output).write_bytes(payload)
            print(f"Setup data ({len(payload)} bytes) written to {args.output}")
        else:
            print(f"Setup data ({len(payload)} bytes):")
            print(payload.hex())

    if args.amitse:
        payload = modifier.read_amitse_data()
        if args.output:
            Path(args.output).write_bytes(payload)
            print(f"AMITSE data ({len(payload)} bytes) written to {args.output}")
        else:
            print(f"AMITSE data ({len(payload)} bytes):")
            print(payload.hex())

    if not args.setup and not args.amitse:
        # Default: dump both
        setup = modifier.read_setup_data()
        amitse = modifier.read_amitse_data()
        print(f"Setup data ({len(setup)} bytes):")
        print(setup.hex())
        print(f"\nAMITSE data ({len(amitse)} bytes):")
        print(amitse.hex())

    return 0


def cmd_preset(args: argparse.Namespace) -> int:
    """Apply a predefined preset (e.g. 'unlock-all', 'rebar-prep')."""
    rom_path = Path(args.rom)
    try:
        original_data = validate_rom(rom_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    preset_name = args.preset_name.lower()
    if preset_name == "unlock-all":
        target_names = [
            "above_4g_decoding",
            "amd_cbs_menu",
            "amd_pbs_menu",
            "nbio_menu",
            "fch_menu",
            "iommu",
            "svm_mode",
        ]
    elif preset_name == "rebar-prep":
        target_names = [
            "above_4g_decoding",
            "large_bar_support",
            "iommu",
        ]
    elif preset_name == "vfio-prep":
        target_names = [
            "above_4g_decoding",
            "iommu",
            "acs_override",
            "svm_mode",
        ]
    else:
        print(f"Unknown preset '{preset_name}'. Available: unlock-all, rebar-prep, vfio-prep")
        return 1

    mods = [Modification(field=_FIELD_BY_NAME[n], target_value=_FIELD_BY_NAME[n].enabled_value)
            for n in target_names]

    print(f"Preset: {preset_name}")
    print(f"Fields to enable: {', '.join(target_names)}")
    if not args.yes:
        if not ask_yes_no("Apply preset?", default=False):
            print("Aborted.")
            return 130

    backup_path = create_backup(rom_path)
    print(f"Backup created: {backup_path}")

    modifier = BiosModifier(original_data)
    applied = modifier.apply_modifications(mods)

    print(f"Applied {len(applied)} change(s).")
    new_data = modifier.rom_bytes()
    rom_path.write_bytes(new_data)
    print(f"Modified ROM written to: {rom_path}")
    print(f"New SHA256: {sha256_file(rom_path)}")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Modify Lenovo M75s-1 BIOS settings in IMAGEM2C.ROM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all known fields and their current values
  %(prog)s list

  # Enable Above 4G Decoding and AMD CBS menu
  %(prog)s apply above_4g_decoding amd_cbs_menu

  # Toggle a field off explicitly
  %(prog)s apply secure_boot:off

  # Set a field to a specific numeric value
  %(prog)s apply memory_profile=2

  # Apply a preset (unlocks common hidden menus)
  %(prog)s preset unlock-all

  # Dump raw Setup data payload
  %(prog)s dump --setup --output setup.bin
        """,
    )
    parser.add_argument("--rom", type=Path, default=Path("extracted/IMAGEM2C.ROM"),
                        help="Path to IMAGEM2C.ROM (default: extracted/IMAGEM2C.ROM)")
    parser.add_argument("-y", "--yes", action="store_true",
                        help="Skip interactive confirmation (dangerous)")

    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list", help="List known modifiable fields")
    p_list.set_defaults(func=cmd_list)

    # apply
    p_apply = sub.add_parser("apply", help="Apply one or more modifications")
    p_apply.add_argument("mods", nargs="+", help="Field names or name=value pairs")
    p_apply.set_defaults(func=cmd_apply)

    # dump
    p_dump = sub.add_parser("dump", help="Dump raw Setup / AMITSE payloads")
    p_dump.add_argument("--setup", action="store_true", help="Dump Setup data")
    p_dump.add_argument("--amitse", action="store_true", help="Dump AMITSESetup data")
    p_dump.add_argument("-o", "--output", type=Path, help="Write to file instead of stdout")
    p_dump.set_defaults(func=cmd_dump)

    # preset
    p_preset = sub.add_parser("preset", help="Apply a predefined preset")
    p_preset.add_argument("preset_name", choices=["unlock-all", "rebar-prep", "vfio-prep"],
                          help="Preset to apply")
    p_preset.set_defaults(func=cmd_preset)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
