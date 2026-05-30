#!/usr/bin/env python3
"""Lightweight inspection helpers for the Lenovo M75s-1 BIOS images.

The script intentionally uses only Python's standard library so it can run in
minimal recovery/research environments.  It extracts the ISO9660 payload files
from the Lenovo bootable ISO and scans the 32 MiB SPI image for UEFI firmware
volumes, selected ASCII strings, and firmware-file headers.
"""
from __future__ import annotations

import argparse
import hashlib
import mmap
import struct
import sys
import tempfile
import uuid
from pathlib import Path

SECTOR_SIZE = 2048

# UEFI 固件卷头偏移量
FVH_SIGNATURE = b"_FVH"
FVH_SIG_OFFSET = 0x28
FVH_HEADER_SIZE = 0x38
FVH_LENGTH_OFFSET = 0x20
FVH_HEADER_LENGTH_OFFSET = 0x30
FVH_MIN_HEADER_LEN = 0x48

# FFS 文件头常量
FFS_HEADER_SIZE = 24
FFS_SIZE_OFFSET_0 = 20
FFS_SIZE_OFFSET_1 = 21
FFS_SIZE_OFFSET_2 = 22
FFS_TYPE_OFFSET = 18
FFS_GUID_SIZE = 16
FFS_ALIGNMENT = 8
FFS_EMPTY_HEADER = b"\xff" * FFS_HEADER_SIZE
FFS_ZERO_HEADER = b"\x00" * FFS_HEADER_SIZE

SEARCH_TERMS = (
    b"AMITSE",
    b"Setup",
    b"Above 4G",
    b"Re-Size BAR",
    b"Resizable",
    b"XMP",
    b"AMD CBS",
    b"CBS",
    b"NBIO",
    b"IOMMU",
    b"PCI",
)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_iso_root_records(iso: bytes):
    pvd = iso[16 * SECTOR_SIZE : 17 * SECTOR_SIZE]
    if pvd[1:6] != b"CD001":
        raise ValueError("not an ISO9660 primary volume descriptor")
    root = pvd[156 : 156 + 34]
    root_extent = int.from_bytes(root[2:6], "little")
    root_size = int.from_bytes(root[10:14], "little") or SECTOR_SIZE
    data = iso[root_extent * SECTOR_SIZE : root_extent * SECTOR_SIZE + root_size]
    pos = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos = ((pos // SECTOR_SIZE) + 1) * SECTOR_SIZE
            continue
        rec = data[pos : pos + length]
        name_len = rec[32]
        raw_name = rec[33 : 33 + name_len]
        if raw_name not in (b"\x00", b"\x01"):
            name = raw_name.decode("latin1").split(";")[0]
            extent = int.from_bytes(rec[2:6], "little")
            size = int.from_bytes(rec[10:14], "little")
            yield name, extent, size
        pos += length


def extract_iso(iso_path: Path, output_dir: Path) -> list[Path]:
    iso = iso_path.read_bytes()
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, extent, size in parse_iso_root_records(iso):
        safe_name = Path(name).name
        target = output_dir / safe_name
        try:
            target.resolve().relative_to(output_dir.resolve())
        except ValueError:
            raise ValueError(f"Illegal filename, possible path traversal: {name!r}")
        if target.exists():
            print(f"Warning: overwriting existing file: {target}", file=sys.stderr)
        target.write_bytes(iso[extent * SECTOR_SIZE : extent * SECTOR_SIZE + size])
        written.append(target)
    return written


def find_offsets(path: Path, needle: bytes, limit: int = 32) -> list[int]:
    offsets: list[int] = []
    with path.open("rb") as stream:
        with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            start = 0
            while len(offsets) < limit:
                pos = mm.find(needle, start)
                if pos < 0:
                    break
                offsets.append(pos)
                start = pos + 1
    return offsets


def firmware_volumes(data: bytes):
    start = 0
    while True:
        sig = data.find(FVH_SIGNATURE, start)
        if sig < 0:
            break
        header = sig - FVH_SIG_OFFSET
        if header >= 0 and header + FVH_HEADER_SIZE <= len(data):
            fv_len = struct.unpack_from("<Q", data, header + FVH_LENGTH_OFFSET)[0]
            hdr_len = struct.unpack_from("<H", data, header + FVH_HEADER_LENGTH_OFFSET)[0]
            if 0 < fv_len <= len(data) - header and hdr_len >= FVH_MIN_HEADER_LEN:
                yield header, fv_len, hdr_len
        start = sig + 1


def tagged_ffs_files(rom_path: Path):
    data = rom_path.read_bytes()
    for fv_base, fv_len, hdr_len in firmware_volumes(data):
        pos = fv_base + hdr_len
        end = fv_base + fv_len
        while pos < end - FFS_HEADER_SIZE:
            pos = (pos + (FFS_ALIGNMENT - 1)) & ~(FFS_ALIGNMENT - 1)
            header = data[pos : pos + FFS_HEADER_SIZE]
            if header in (FFS_EMPTY_HEADER, FFS_ZERO_HEADER):
                break
            size = (header[FFS_SIZE_OFFSET_0] |
                    (header[FFS_SIZE_OFFSET_1] << 8) |
                    (header[FFS_SIZE_OFFSET_2] << 16))
            if size < FFS_HEADER_SIZE or pos + size > end:
                break
            body = data[pos + FFS_HEADER_SIZE : pos + size].lower()
            tags = [term.decode("latin1") for term in SEARCH_TERMS if term.lower() in body]
            if tags:
                yield {
                    "fv_base": fv_base,
                    "offset": pos,
                    "size": size,
                    "type": header[FFS_TYPE_OFFSET],
                    "guid": str(uuid.UUID(bytes_le=header[:FFS_GUID_SIZE])),
                    "tags": tags,
                }
            pos += size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, default=Path("BIOSCD-M2CJ953USA.iso"))
    parser.add_argument("--rom", type=Path, help="Path to IMAGEM2C.ROM; defaults to extracted ISO payload")
    parser.add_argument("--extract-dir", type=Path, default=Path(tempfile.gettempdir()) / "lenovo_m75s_bios_extract")
    args = parser.parse_args()

    if not args.iso.exists():
        print(f"Error: ISO file not found: {args.iso}", file=sys.stderr)
        return 1

    try:
        print(f"ISO: {args.iso} size={args.iso.stat().st_size} sha256={sha256(args.iso)}")
    except OSError as e:
        print(f"Error: cannot read ISO file: {e}", file=sys.stderr)
        return 1

    extracted = extract_iso(args.iso, args.extract_dir)
    for path in extracted:
        print(f"extracted: {path.name} size={path.stat().st_size} sha256={sha256(path)}")

    rom = args.rom or args.extract_dir / "IMAGEM2C.ROM"
    if not rom.exists():
        print(f"Error: ROM file not found: {rom}, specify --rom manually", file=sys.stderr)
        return 1
    print(f"\nROM: {rom} size={rom.stat().st_size} sha256={sha256(rom)}")
    print("\nKey string offsets:")
    for term in SEARCH_TERMS:
        offsets = find_offsets(rom, term)
        rendered = ", ".join(hex(x) for x in offsets[:12]) or "none"
        print(f"  {term.decode('latin1')}: {rendered}")

    print("\nFirmware volumes:")
    for base, length, hdr_len in firmware_volumes(rom):
        print(f"  base={base:#010x} length={length:#x} header={hdr_len:#x}")

    print("\nTagged FFS files:")
    for item in tagged_ffs_files(rom):
        print(
            "  "
            f"fv={item['fv_base']:#010x} off={item['offset']:#010x} "
            f"size={item['size']:#x} type={item['type']:#x} "
            f"guid={item['guid']} tags={','.join(item['tags'])}"
        )


if __name__ == "__main__":
    sys.exit(main())
