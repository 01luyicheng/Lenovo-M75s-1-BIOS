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
import uuid
from pathlib import Path

SECTOR_SIZE = 2048
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
        target = output_dir / name
        target.write_bytes(iso[extent * SECTOR_SIZE : extent * SECTOR_SIZE + size])
        written.append(target)
    return written


def find_offsets(path: Path, needle: bytes, limit: int = 32) -> list[int]:
    offsets: list[int] = []
    with path.open("rb") as stream:
        mm = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        start = 0
        while len(offsets) < limit:
            pos = mm.find(needle, start)
            if pos < 0:
                break
            offsets.append(pos)
            start = pos + 1
        mm.close()
    return offsets


def firmware_volumes(rom_path: Path):
    data = rom_path.read_bytes()
    start = 0
    while True:
        sig = data.find(b"_FVH", start)
        if sig < 0:
            break
        header = sig - 0x28
        if header >= 0 and header + 0x38 <= len(data):
            fv_len = struct.unpack_from("<Q", data, header + 0x20)[0]
            hdr_len = struct.unpack_from("<H", data, header + 0x30)[0]
            if 0 < fv_len <= len(data) - header and hdr_len >= 0x48:
                yield header, fv_len, hdr_len
        start = sig + 1


def tagged_ffs_files(rom_path: Path):
    data = rom_path.read_bytes()
    for fv_base, fv_len, hdr_len in firmware_volumes(rom_path):
        pos = fv_base + hdr_len
        end = fv_base + fv_len
        while pos < end - 24:
            pos = (pos + 7) & ~7
            header = data[pos : pos + 24]
            if header in (b"\xff" * 24, b"\x00" * 24):
                break
            size = header[20] | (header[21] << 8) | (header[22] << 16)
            if size < 24 or pos + size > end:
                break
            body = data[pos + 24 : pos + size].lower()
            tags = [term.decode("latin1") for term in SEARCH_TERMS if term.lower() in body]
            if tags:
                yield {
                    "fv_base": fv_base,
                    "offset": pos,
                    "size": size,
                    "type": header[18],
                    "guid": str(uuid.UUID(bytes_le=header[:16])),
                    "tags": tags,
                }
            pos += size


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, default=Path("BIOSCD-M2CJ953USA.iso"))
    parser.add_argument("--rom", type=Path, help="Path to IMAGEM2C.ROM; defaults to extracted ISO payload")
    parser.add_argument("--extract-dir", type=Path, default=Path("/tmp/lenovo_m75s_bios_extract"))
    args = parser.parse_args()

    print(f"ISO: {args.iso} size={args.iso.stat().st_size} sha256={sha256(args.iso)}")
    extracted = extract_iso(args.iso, args.extract_dir)
    for path in extracted:
        print(f"extracted: {path.name} size={path.stat().st_size} sha256={sha256(path)}")

    rom = args.rom or args.extract_dir / "IMAGEM2C.ROM"
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
    main()
