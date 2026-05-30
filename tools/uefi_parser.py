#!/usr/bin/env python3
"""UEFI Firmware Volume and FFS file parser for Lenovo M75s-1 BIOS.

This module parses UEFI Firmware Volume (FV) structures and Firmware File System
(FFS) files from a raw BIOS ROM image. It supports:

* Parsing Firmware Volume Headers (_FVH signature, GUID, attributes, length)
* Iterating over all firmware volumes in the image
* Extracting FFS files from each volume
* Recognising common compression types (LZMA, TIANO, etc.)
* Command-line tree output of volumes and files

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import struct
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Iterator, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FVH_SIGNATURE = b"_FVH"
FVH_SIG_OFFSET = 0x28          # signature is at offset 0x28 within the FV header
FVH_MIN_HEADER_LEN = 0x48      # minimum valid header length

# Offsets within the FV header (relative to the start of the volume)
FVH_ZERO_VECTOR_OFFSET = 0x00  # 16 bytes
FVH_FILE_SYSTEM_GUID_OFFSET = 0x10  # 16 bytes
FVH_FV_LENGTH_OFFSET = 0x20    # 8 bytes (UINT64)
FVH_SIGNATURE_OFFSET = 0x28    # 4 bytes
FVH_ATTRIBUTES_OFFSET = 0x2C   # 4 bytes (UINT32)
FVH_HEADER_LENGTH_OFFSET = 0x30  # 2 bytes (UINT16)
FVH_CHECKSUM_OFFSET = 0x32     # 2 bytes (UINT16)
FVH_EXT_HEADER_OFFSET_OFFSET = 0x34  # 2 bytes (UINT16)
FVH_RESERVED_OFFSET = 0x36     # 1 byte
FVH_REVISION_OFFSET = 0x37     # 1 byte

# FFS file header constants
FFS_HEADER_SIZE = 24
FFS_GUID_SIZE = 16
FFS_SIZE_OFFSET_0 = 20         # 24-bit size, little-endian
FFS_SIZE_OFFSET_1 = 21
FFS_SIZE_OFFSET_2 = 22
FFS_TYPE_OFFSET = 18
FFS_ATTRIBUTES_OFFSET = 19
FFS_STATE_OFFSET = 23
FFS_ALIGNMENT = 8

FFS_EMPTY_HEADER = b"\xff" * FFS_HEADER_SIZE
FFS_ZERO_HEADER = b"\x00" * FFS_HEADER_SIZE

# FFS file types (UEFI PI Specification)
FFS_FILE_TYPES: dict[int, str] = {
    0x00: "All (not a file)",
    0x01: "Raw",
    0x02: "Freeform",
    0x03: "Security core",
    0x04: "PEI core",
    0x05: "DXE core",
    0x06: "PEIM",
    0x07: "Driver",
    0x08: "Combined PEIM/Driver",
    0x09: "Application",
    0x0A: "SMM",
    0x0B: "Firmware volume image",
    0x0C: "Combined SMM/DXE",
    0x0D: "SMM core",
    0x0E: "SMM standalone",
    0x0F: "SMM core standalone",
    0xF0: "FFS padding",
}

# Section types (UEFI PI Specification)
SECTION_TYPES: dict[int, str] = {
    0x01: "Compression",
    0x02: "GUID defined",
    0x10: "PE32",
    0x11: "PIC",
    0x12: "TE",
    0x13: "DXE_DEPEX",
    0x14: "Version",
    0x15: "User interface",
    0x16: "Compatibility",
    0x17: "Firmware volume image",
    0x18: "Freeform subtype GUID",
    0x19: "Raw",
    0x1B: "PEI_DEPEX",
    0x1C: "MM_DEPEX",
}

# Compression section algorithm GUIDs
COMPRESSION_GUIDS: dict[str, str] = {
    "ee4e5898-3914-4259-9d6e-dc7bd79403cf": "LZMA",
    "d42ae6bd-1352-4bfb-909a-ca72a6eae889": "LZMAF86",
    "a31280ad-481e-41b6-95e8-127f4c984779": "TIANO",
    "fc1bcdb0-7d31-49aa-936a-a4600d9dd083": "LZMA",
}

# Known FV GUIDs (human-readable names)
FV_GUID_NAMES: dict[str, str] = {
    "8d2bf1ff-9676-4b8c-a985-2747075b4f50": "PI Firmware Volume",
    "fff12b8d-7696-4c8b-a985-2747075b4f50": "System Firmware Volume",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FirmwareVolumeHeader:
    """Parsed UEFI Firmware Volume Header."""

    offset: int
    zero_vector: bytes
    file_system_guid: uuid.UUID
    fv_length: int
    signature: bytes
    attributes: int
    header_length: int
    checksum: int
    ext_header_offset: int
    reserved: int
    revision: int

    @property
    def file_system_guid_name(self) -> str | None:
        return FV_GUID_NAMES.get(str(self.file_system_guid).lower())

    @property
    def attributes_str(self) -> str:
        """Return a human-readable description of FV attributes."""
        attrs = []
        if self.attributes & 0x00000001:
            attrs.append("WriteDisable")
        if self.attributes & 0x00000002:
            attrs.append("WriteEnable")
        if self.attributes & 0x00000004:
            attrs.append("WriteStatus")
        if self.attributes & 0x00000008:
            attrs.append("ReadDisable")
        if self.attributes & 0x00000010:
            attrs.append("ReadEnable")
        if self.attributes & 0x00000020:
            attrs.append("ReadStatus")
        if self.attributes & 0x00000040:
            attrs.append("Lock")
        if self.attributes & 0x00000080:
            attrs.append("StickyWrite")
        if self.attributes & 0x00000100:
            attrs.append("MemoryMapped")
        if self.attributes & 0x00000200:
            attrs.append("ErasePolarity")
        if self.attributes & 0x00000400:
            attrs.append("Alignment")
        if self.attributes & 0x00000800:
            attrs.append("Weakening")
        if self.attributes & 0x00008000:
            attrs.append("EraseCapabilities")
        return " | ".join(attrs) if attrs else "None"


@dataclass(frozen=True, slots=True)
class FFSSection:
    """A section inside an FFS file."""

    offset: int
    section_type: int
    size: int
    data: bytes
    guid: uuid.UUID | None = None

    @property
    def type_name(self) -> str:
        return SECTION_TYPES.get(self.section_type, f"Unknown(0x{self.section_type:02X})")

    @property
    def compression_type(self) -> str | None:
        """Detect compression type from GUID-defined or compression sections."""
        if self.section_type == 0x01 and len(self.data) >= 16:
            # Compression section: first 16 bytes are the GUID
            guid = str(uuid.UUID(bytes_le=self.data[:16])).lower()
            return COMPRESSION_GUIDS.get(guid, f"Unknown({guid})")
        if self.section_type == 0x02 and len(self.data) >= 16:
            guid = str(uuid.UUID(bytes_le=self.data[:16])).lower()
            return COMPRESSION_GUIDS.get(guid, f"GUID-defined({guid})")
        return None


@dataclass(frozen=True, slots=True)
class FFSFile:
    """Parsed FFS file header + payload."""

    offset: int
    name_guid: uuid.UUID
    file_type: int
    attributes: int
    size: int
    state: int
    data: bytes
    sections: list[FFSSection] = field(default_factory=list, repr=False)

    @property
    def type_name(self) -> str:
        return FFS_FILE_TYPES.get(self.file_type, f"Unknown(0x{self.file_type:02X})")

    @property
    def is_pad(self) -> bool:
        return self.file_type == 0xF0

    @property
    def compression_info(self) -> list[str]:
        """Return list of compression types found in sections."""
        result: list[str] = []
        for sec in self.sections:
            ct = sec.compression_type
            if ct and ct not in result:
                result.append(ct)
        return result


@dataclass(frozen=True, slots=True)
class FirmwareVolume:
    """A firmware volume with its header and contained FFS files."""

    offset: int
    header: FirmwareVolumeHeader
    data: bytes
    files: list[FFSFile] = field(default_factory=list, repr=False)


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

def _read_uint24(data: bytes, offset: int) -> int:
    """Read a 24-bit little-endian integer."""
    return (
        data[offset]
        | (data[offset + 1] << 8)
        | (data[offset + 2] << 16)
    )


def _align_up(value: int, alignment: int) -> int:
    """Align *value* up to the nearest *alignment* boundary."""
    return (value + alignment - 1) & ~(alignment - 1)


def _parse_sections(data: bytes, base_offset: int) -> list[FFSSection]:
    """Parse UEFI sections from the raw payload of an FFS file."""
    sections: list[FFSSection] = []
    pos = 0
    end = len(data)
    while pos + 4 <= end:
        # Section size is 3 bytes (24-bit), section type is 1 byte
        sec_size = _read_uint24(data, pos)
        sec_type = data[pos + 3]
        if sec_size < 4 or pos + sec_size > end:
            break
        sec_data = data[pos + 4 : pos + sec_size]
        guid = None
        if sec_type in (0x01, 0x02) and len(sec_data) >= 16:
            guid = uuid.UUID(bytes_le=sec_data[:16])
        sections.append(
            FFSSection(
                offset=base_offset + pos,
                section_type=sec_type,
                size=sec_size,
                data=sec_data,
                guid=guid,
            )
        )
        pos = _align_up(pos + sec_size, 4)
    return sections


# ---------------------------------------------------------------------------
# Core parser
# ---------------------------------------------------------------------------

class UEFIParser:
    """Parser for UEFI firmware volumes and FFS files."""

    def __init__(self, data: bytes) -> None:
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("data must be bytes or bytearray")
        self.data = bytes(data)
        self._volumes: list[FirmwareVolume] | None = None

    # ------------------------------------------------------------------
    # Firmware Volume discovery
    # ------------------------------------------------------------------

    @classmethod
    def from_file(cls, path: Path | str) -> "UEFIParser":
        """Create a parser from a file path."""
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"File not found: {p}")
        return cls(p.read_bytes())

    def iter_fv_headers(self) -> Iterator[FirmwareVolumeHeader]:
        """Iterate over all valid Firmware Volume Headers in the image."""
        start = 0
        data = self.data
        data_len = len(data)
        while True:
            sig_pos = data.find(FVH_SIGNATURE, start)
            if sig_pos < 0:
                break
            header_offset = sig_pos - FVH_SIG_OFFSET
            if header_offset < 0 or header_offset + FVH_MIN_HEADER_LEN > data_len:
                start = sig_pos + 1
                continue
            # Parse fields
            zero_vector = data[header_offset + FVH_ZERO_VECTOR_OFFSET :
                               header_offset + FVH_ZERO_VECTOR_OFFSET + 16]
            fs_guid = uuid.UUID(
                bytes_le=data[header_offset + FVH_FILE_SYSTEM_GUID_OFFSET :
                              header_offset + FVH_FILE_SYSTEM_GUID_OFFSET + 16]
            )
            fv_length = struct.unpack_from("<Q", data, header_offset + FVH_FV_LENGTH_OFFSET)[0]
            signature = data[header_offset + FVH_SIGNATURE_OFFSET :
                             header_offset + FVH_SIGNATURE_OFFSET + 4]
            attributes = struct.unpack_from("<I", data, header_offset + FVH_ATTRIBUTES_OFFSET)[0]
            header_length = struct.unpack_from("<H", data, header_offset + FVH_HEADER_LENGTH_OFFSET)[0]
            checksum = struct.unpack_from("<H", data, header_offset + FVH_CHECKSUM_OFFSET)[0]
            ext_header_offset = struct.unpack_from("<H", data, header_offset + FVH_EXT_HEADER_OFFSET_OFFSET)[0]
            reserved = data[header_offset + FVH_RESERVED_OFFSET]
            revision = data[header_offset + FVH_REVISION_OFFSET]

            # Validation
            if signature != FVH_SIGNATURE:
                start = sig_pos + 1
                continue
            if fv_length == 0 or fv_length > data_len - header_offset:
                start = sig_pos + 1
                continue
            if header_length < FVH_MIN_HEADER_LEN or header_length > fv_length:
                start = sig_pos + 1
                continue

            yield FirmwareVolumeHeader(
                offset=header_offset,
                zero_vector=zero_vector,
                file_system_guid=fs_guid,
                fv_length=fv_length,
                signature=signature,
                attributes=attributes,
                header_length=header_length,
                checksum=checksum,
                ext_header_offset=ext_header_offset,
                reserved=reserved,
                revision=revision,
            )
            start = header_offset + fv_length

    def iter_volumes(self) -> Iterator[FirmwareVolume]:
        """Iterate over all firmware volumes, parsing contained FFS files."""
        for hdr in self.iter_fv_headers():
            fv_data = self.data[hdr.offset : hdr.offset + hdr.fv_length]
            files = list(self._iter_ffs_files(hdr.offset, hdr.header_length, hdr.fv_length))
            yield FirmwareVolume(
                offset=hdr.offset,
                header=hdr,
                data=fv_data,
                files=files,
            )

    def get_volumes(self) -> list[FirmwareVolume]:
        """Return a cached list of all firmware volumes."""
        if self._volumes is None:
            self._volumes = list(self.iter_volumes())
        return self._volumes

    # ------------------------------------------------------------------
    # FFS file parsing
    # ------------------------------------------------------------------

    def _iter_ffs_files(
        self, fv_base: int, header_length: int, fv_length: int
    ) -> Iterator[FFSFile]:
        """Iterate over FFS files within a single firmware volume."""
        pos = fv_base + header_length
        end = fv_base + fv_length
        data = self.data
        while pos < end - FFS_HEADER_SIZE:
            pos = _align_up(pos, FFS_ALIGNMENT)
            if pos >= end - FFS_HEADER_SIZE:
                break
            header = data[pos : pos + FFS_HEADER_SIZE]
            if header == FFS_EMPTY_HEADER or header == FFS_ZERO_HEADER:
                # Empty / erased space - skip ahead in larger steps
                pos += FFS_ALIGNMENT
                continue
            size = _read_uint24(header, FFS_SIZE_OFFSET_0)
            if size < FFS_HEADER_SIZE or pos + size > end:
                # Corrupt or misaligned - try to recover
                pos += FFS_ALIGNMENT
                continue
            file_type = header[FFS_TYPE_OFFSET]
            attributes = header[FFS_ATTRIBUTES_OFFSET]
            state = header[FFS_STATE_OFFSET]
            name_guid = uuid.UUID(bytes_le=header[:FFS_GUID_SIZE])
            file_data = data[pos + FFS_HEADER_SIZE : pos + size]
            sections = _parse_sections(file_data, pos + FFS_HEADER_SIZE)
            yield FFSFile(
                offset=pos,
                name_guid=name_guid,
                file_type=file_type,
                attributes=attributes,
                size=size,
                state=state,
                data=file_data,
                sections=sections,
            )
            pos += size

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def find_files_by_guid(self, guid: str | uuid.UUID) -> list[FFSFile]:
        """Find all FFS files matching the given GUID."""
        target = uuid.UUID(str(guid))
        results: list[FFSFile] = []
        for vol in self.get_volumes():
            for f in vol.files:
                if f.name_guid == target:
                    results.append(f)
        return results

    def find_files_by_type(self, file_type: int) -> list[FFSFile]:
        """Find all FFS files of a given type."""
        results: list[FFSFile] = []
        for vol in self.get_volumes():
            for f in vol.files:
                if f.file_type == file_type:
                    results.append(f)
        return results

    def find_compressed_files(self) -> list[FFSFile]:
        """Find all FFS files that contain compressed sections."""
        results: list[FFSFile] = []
        for vol in self.get_volumes():
            for f in vol.files:
                if f.compression_info:
                    results.append(f)
        return results

    def get_statistics(self) -> dict[str, int]:
        """Return basic statistics about the parsed image."""
        stats: dict[str, int] = {
            "total_volumes": 0,
            "total_files": 0,
            "total_sections": 0,
            "compressed_files": 0,
            "pad_files": 0,
        }
        for vol in self.get_volumes():
            stats["total_volumes"] += 1
            for f in vol.files:
                stats["total_files"] += 1
                stats["total_sections"] += len(f.sections)
                if f.compression_info:
                    stats["compressed_files"] += 1
                if f.is_pad:
                    stats["pad_files"] += 1
        return stats


# ---------------------------------------------------------------------------
# Tree printer (CLI)
# ---------------------------------------------------------------------------

def _print_tree(
    parser: UEFIParser,
    show_sections: bool = False,
    show_compression: bool = True,
    max_files: int | None = None,
) -> None:
    """Print a tree representation of firmware volumes and FFS files."""
    volumes = parser.get_volumes()
    if not volumes:
        print("No firmware volumes found.")
        return

    print(f"UEFI Firmware Image ({len(parser.data)} bytes)")
    print(f"├── Found {len(volumes)} Firmware Volume(s)")

    for vi, vol in enumerate(volumes):
        vol_last = vi == len(volumes) - 1
        vol_prefix = "    " if vol_last else "│   "
        vol_connector = "└── " if vol_last else "├── "

        hdr = vol.header
        guid_str = str(hdr.file_system_guid)
        guid_name = hdr.file_system_guid_name or "Unknown FV"
        print(
            f"{vol_connector}FV @ 0x{hdr.offset:08X} "
            f"(len=0x{hdr.fv_length:X}, hdr=0x{hdr.header_length:X})"
        )
        print(f"{vol_prefix}├── GUID : {guid_name}")
        print(f"{vol_prefix}├── FSG  : {guid_str}")
        print(f"{vol_prefix}├── Attr : 0x{hdr.attributes:08X} ({hdr.attributes_str})")
        print(f"{vol_prefix}├── Rev  : {hdr.revision}")

        files = vol.files
        if max_files is not None:
            files = files[:max_files]

        if not files:
            print(f"{vol_prefix}└── (no FFS files)")
            continue

        print(f"{vol_prefix}├── Files: {len(vol.files)}")
        for fi, f in enumerate(files):
            f_last = fi == len(files) - 1
            f_prefix = vol_prefix + ("    " if f_last else "│   ")
            f_connector = vol_prefix + ("└── " if f_last else "├── ")

            comp_str = ""
            if show_compression and f.compression_info:
                comp_str = f" [{', '.join(f.compression_info)}]"

            print(
                f"{f_connector}FFS @ 0x{f.offset:08X} "
                f"size=0x{f.size:X} type=0x{f.file_type:02X} ({f.type_name})"
                f"{comp_str}"
            )
            print(f"{f_prefix}├── GUID : {f.name_guid}")
            print(f"{f_prefix}├── Attr : 0x{f.attributes:02X}")
            print(f"{f_prefix}├── State: 0x{f.state:02X}")

            if show_sections and f.sections:
                print(f"{f_prefix}├── Sections: {len(f.sections)}")
                for si, sec in enumerate(f.sections):
                    s_last = si == len(f.sections) - 1
                    s_connector = f_prefix + ("└── " if s_last else "├── ")
                    comp = sec.compression_type
                    extra = f" -> {comp}" if comp else ""
                    print(
                        f"{s_connector}SEC @ 0x{sec.offset:08X} "
                        f"type=0x{sec.section_type:02X} ({sec.type_name}) "
                        f"size=0x{sec.size:X}{extra}"
                    )
            else:
                print(f"{f_prefix}└── Sections: {len(f.sections)}")


def _print_summary(parser: UEFIParser) -> None:
    """Print a concise summary of the parsed image."""
    stats = parser.get_statistics()
    print("\nSummary:")
    print(f"  Total firmware volumes : {stats['total_volumes']}")
    print(f"  Total FFS files        : {stats['total_files']}")
    print(f"  Total sections         : {stats['total_sections']}")
    print(f"  Compressed files       : {stats['compressed_files']}")
    print(f"  Pad files              : {stats['pad_files']}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Parse UEFI Firmware Volumes and FFS files from a BIOS ROM image."
    )
    parser.add_argument("rom", type=Path, help="Path to the BIOS ROM file (e.g. IMAGEM2C.ROM)")
    parser.add_argument(
        "--tree", action="store_true", default=True, help="Print tree output (default)"
    )
    parser.add_argument(
        "--no-tree", action="store_true", help="Disable tree output, show summary only"
    )
    parser.add_argument(
        "--sections", action="store_true", help="Show individual sections inside each FFS file"
    )
    parser.add_argument(
        "--no-compression", action="store_true", help="Hide compression type annotations"
    )
    parser.add_argument(
        "--max-files", type=int, default=None, help="Limit the number of files shown per volume"
    )
    parser.add_argument(
        "--find-guid", type=str, default=None, help="Find FFS files by GUID"
    )
    parser.add_argument(
        "--find-type", type=int, default=None, help="Find FFS files by type (integer)"
    )
    parser.add_argument(
        "--compressed-only", action="store_true", help="List only compressed files"
    )
    args = parser.parse_args()

    rom_path = args.rom
    if not rom_path.exists():
        print(f"Error: ROM file not found: {rom_path}", file=sys.stderr)
        return 1

    try:
        uefi = UEFIParser.from_file(rom_path)
    except Exception as exc:
        print(f"Error reading ROM: {exc}", file=sys.stderr)
        return 1

    # Search modes
    if args.find_guid:
        try:
            results = uefi.find_files_by_guid(args.find_guid)
        except ValueError as exc:
            print(f"Invalid GUID: {exc}", file=sys.stderr)
            return 1
        print(f"Found {len(results)} file(s) with GUID {args.find_guid}:")
        for f in results:
            print(
                f"  0x{f.offset:08X} size=0x{f.size:X} type={f.type_name} guid={f.name_guid}"
            )
        return 0

    if args.find_type is not None:
        results = uefi.find_files_by_type(args.find_type)
        print(f"Found {len(results)} file(s) of type 0x{args.find_type:02X}:")
        for f in results:
            print(f"  0x{f.offset:08X} size=0x{f.size:X} guid={f.name_guid}")
        return 0

    if args.compressed_only:
        results = uefi.find_compressed_files()
        print(f"Found {len(results)} compressed file(s):")
        for f in results:
            comps = ", ".join(f.compression_info)
            print(
                f"  0x{f.offset:08X} size=0x{f.size:X} [{comps}] guid={f.name_guid}"
            )
        return 0

    # Default / tree output
    if not args.no_tree:
        _print_tree(
            uefi,
            show_sections=args.sections,
            show_compression=not args.no_compression,
            max_files=args.max_files,
        )

    _print_summary(uefi)
    return 0


if __name__ == "__main__":
    sys.exit(main())
