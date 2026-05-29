# Lenovo M75s-1 BIOS mod feasibility notes

This repository currently contains Lenovo M75s-1 firmware update packages, not an already-unpacked UEFI tree.  The analysis below was produced from the bootable ISO and the 32 MiB `IMAGEM2C.ROM` extracted from it.

## Source images

| File | Size | SHA256 | Notes |
| --- | ---: | --- | --- |
| `BIOS-M2CJY53USA.exe` | 19,331,608 bytes | `639bad1ea7ae2045af73388249ac9cd9525486ad0c93415037ded49b3d143bf6` | Windows update package; strings indicate an Inno Setup wrapper. |
| `BIOSCD-M2CJ953USA.iso` | 100,726,784 bytes | `f7b6929fccde8f74efd4fb8bce44f375dd4569db6abd70005a46e643eed0ded4` | Bootable flash ISO; contains the main ROM and UEFI Shell flashing image. |

The ISO root contains these payloads:

| ISO payload | Size | SHA256 | Purpose |
| --- | ---: | --- | --- |
| `CHANGES.TXT` | 2,455 bytes | `1d61f5317f1e9c62d2fca1b26a31b6b86bbfd92797bf7c083be77086390e4791` | Lenovo change log. |
| `IMAGEM2C.ROM` | 33,554,432 bytes | `8fb2f1044a3d79320afa0e5efdcf3c868c6bf7d17064c868eb4ed811b6adf8e9` | Main 32 MiB UEFI/SPI image and the primary research target. |
| `M2CJT53A.IMG` | 67,108,864 bytes | `4ca889d24405dc54ce007cddcbb0160e3a09fe599c930d93c86a0a56515df2a3` | FAT-formatted UEFI Shell flash image. |
| `README.TXT` | 12,503 bytes | `c425c10a087ec1fd717de871476a9ad3ace83af5f060164b408933bbfde357d9` | Lenovo flashing and tooling notes. |

The UEFI Shell image includes `STARTUP.NSH`, `FLASH2.EFI`, `AfuEfix64.efi`, `AMIDEEFIx64.efi`, logo tools, and another copy of `IMAGEM2C.ROM`.  `STARTUP.NSH` ultimately calls `flash2.efi imageM2C.rom /bb /rsmb`; the README describes `/rsmb`, `/clr`, `/ign`, `/quiet`, and password-related flash options.

## Lightweight inspection helper

`tools/inspect_bios.py` was added as a reproducible, dependency-free inspection helper.  It uses only the Python standard library to:

1. parse the ISO9660 root directory;
2. extract the ISO payloads into `/tmp/lenovo_m75s_bios_extract` by default;
3. compute SHA256 hashes;
4. find key strings in `IMAGEM2C.ROM`;
5. identify `_FVH` firmware volumes;
6. walk simple FFS file headers and report files whose bodies contain keywords such as `Setup`, `AMITSE`, `Above 4G`, `CBS`, `NBIO`, `IOMMU`, and `PCI`.

This helper is not a replacement for UEFITool NE, UEFIExtract, IFRExtractor, AMITSE parsers, or a disassembler.  It is intended to make the first-pass evidence repeatable in this minimal environment.

## UEFI firmware volume layout

The 32 MiB `IMAGEM2C.ROM` contains multiple valid UEFI firmware volumes:

| FV base | Length | Notes |
| ---: | ---: | --- |
| `0x00000000` | `0x20000` | Firmware volume. |
| `0x00037000` | `0x20000` | NVRAM/variable-area candidate. |
| `0x00077000` | `0x20000` | Firmware volume. |
| `0x006cf000` | `0x631000` | Large firmware volume / encapsulated content candidate. |
| `0x006e1488` | `0x20000` | Embedded firmware volume. |
| `0x00d00000` | `0x300000` | AMD/PEI platform modules are concentrated here. |
| `0x01000000` | `0x20000` | Firmware volume. |
| `0x01037000` | `0x20000` | Mirrored NVRAM/variable-area candidate. |
| `0x01077000` | `0x20000` | Firmware volume. |
| `0x01411000` | `0x8ef000` | Large firmware volume / alternate image area. |
| `0x01423488` | `0x20000` | Embedded firmware volume. |
| `0x01d00000` | `0x300000` | Large FFS blob. |
| `0x01d02000` | `0x2fe000` | AMD/PEI platform modules. |

The duplicate-looking `0x00037000` and `0x01037000` areas both contain `AMITSESetup`, `Setup`, and related variable names, so treat them as mirrored or redundant variable/default-store evidence until a full NVAR parser confirms the exact role.

## Setup, AMITSE, and NVRAM evidence

The ROM contains AMI setup-related NVAR names and short variable payloads.  Important findings:

| Variable/string | Approximate ROM evidence | Current interpretation |
| --- | --- | --- |
| `StdDefaults` | around `0x00037090` and `0x01037090` | Default-variable block evidence. |
| `Setup` | around `0x000370a7` and `0x010370a7`; data area begins around `0x000370b8` / `0x010370b8`, length about `0x20d` | Main BIOS setup variable likely exists, but offsets inside it are not known without IFR. |
| `AMITSESetup` | around `0x000372f8` and `0x010372f8`; data area begins around `0x0003730f` / `0x0103730f`, length about `0x183` | AMI TSE/setup UI state variable candidate. |
| `SecureBootSetup` | around `0x000375f1` and `0x010375f1`; payload appears to be `01 01 01 00 00 00 00` | Secure Boot setup-state variable candidate; not the whole Secure Boot key/state model. |
| `ROM_CMN` | around `0x00037613` and `0x01037613`, length about `0xfc` | Platform common setup-state candidate. |
| `PCI_COMMON` | around `0x00037722` and `0x01037722`, length about `0x7`, default bytes all zero | PCI-related setup-state candidate; field meanings are unknown without IFR or reverse engineering. |

Do not use these ROM offsets directly as `setup_var` offsets.  `setup_var` requires IFR `VarStore` and question `VarOffset` information, while the offsets above are flash-image offsets in the NVAR/default-store area.

## Hidden settings and XMP assessment

Current evidence does **not** prove that XMP/A-XMP or a full AMD CBS/PBS setup page is already present but hidden.

Findings:

- `Setup` and `AMITSESetup` variables exist.
- CBS-related platform modules and strings exist, including `CbsBasePeiZP`, `CbsBasePeiRV`, `CbsBasePeiSSP`, and `FchPromontoryCbsPei`-style evidence.
- NBIO, IOMMU, GNB, PCIe, and memory-initialization modules are present.
- Directly readable strings do **not** show clear `AMD CBS`, `AMD PBS`, `A-XMP`, `D.O.C.P.`, `Memory Profile`, or XMP setup-menu text.
- A raw `XMP` byte sequence can appear inside large binary blobs, but there is no readable HII/IFR menu evidence tying it to a user-facing option.

Practical conclusion: XMP is not currently a safe “just unhide it” target.  If later IFR extraction finds XMP/DRAM questions, they can be mapped to `Setup`/AMD setup variable offsets.  If IFR has no such questions, XMP would require AGESA/memory-policy-level work or HII/menu transplanting, which is substantially riskier.

## Resizable BAR / Above 4G assessment

### What is present

The firmware contains bottom-layer evidence for PCIe and 64-bit MMIO resource handling:

- `Above 4G` strings exist, including messages about `Above 4G MMIO base`, no MMIO space above 4G, and user requests for above-4G prefetchable MMIO size/alignment.
- NBIO/GNB/PCIe modules exist, including `AmdNbioPcie*Pei` and `GnbSetTom*`-style evidence.
- Resource-distribution strings exist, including TOM/TOM2, PCIe configuration space, per-root-bridge resource sizing, and above-4G prefetch/non-prefetch MMIO allocation.
- UEFI Shell PCI diagnostic text includes Resizable BAR capability strings such as `Resizeable Bar Capability`, `ResizableBarCapability`, and `ResizableBarControl`.

### What is not currently proven

The current image does **not** show clear evidence of a user-facing or policy-level ReBAR implementation:

- no clear `Re-Size BAR Support` setup string;
- no clear `Resizable BAR` setup string;
- no clear `Smart Access Memory` setup string;
- no proven IFR question or setup variable for ReBAR;
- no proven DXE policy that chooses GPU BAR size before PCI resource allocation.

The UEFI Shell PCI strings only show that the Shell can decode the PCIe Resizable BAR extended capability.  They do not mean the platform firmware enables GPU ReBAR.

### Feasibility conclusion

Adding real Resizable BAR support is likely more than a menu-unlock change.  A working implementation generally needs all of these:

1. CSM disabled and UEFI GOP-compatible GPU boot.
2. Above 4G / large 64-bit prefetchable MMIO aperture.
3. PCI host bridge and PciBus resource allocation that can assign a very large GPU BAR.
4. Policy code that scans PCIe Extended Capability ID `0x15`, chooses a supported BAR size, writes the Resizable BAR Control register, and does so early enough for subsequent PCI resource sizing.
5. ACPI root bridge resources that remain consistent with the assigned large BAR.
6. GPU VBIOS and OS/driver support.

Therefore, the recommended sequence is to first prove or enable Above 4G resource allocation, then determine whether any hidden ReBAR policy exists.  If no ReBAR policy exists, the next step is binary comparison against a similar Lenovo/AMI AM4 BIOS that already supports ReBAR.

## Recommended next work

1. Open `IMAGEM2C.ROM` with UEFITool NE or UEFIExtract and recursively extract compressed/guided sections.
2. Locate `Setup`, `AMITSE`, HII package lists, and any SetupUtility-style module.
3. Run IFRExtractor or ifrextract-rs on every candidate PE32/HII body.
4. Search IFR output for `AMD CBS`, `AMD PBS`, `CBS`, `NBIO`, `IOMMU`, `Above 4G`, `PCIe`, `XMP`, `A-XMP`, `DRAM Timing`, `Memory Frequency`, `CSM`, and `Secure Boot`.
5. If a question is found, record `VarStore`, `VarStoreId`, `QuestionId`, `VarOffset`, width, default value, and any `SuppressIf` or `GrayOutIf` condition before attempting `setup_var`.
6. If no question is found for the desired feature, treat it as a policy/HII transplant or DXE/AGESA reverse-engineering task, not a simple setup unlock.
7. Before flashing any modified ROM, make a full external SPI dump and prepare a hardware recovery path.

## Baseline validation suggestions

Before any modification, record a hardware baseline:

- In UEFI Shell, inspect the GPU and root ports with `pci` and `pci <bus> <dev> <fn> -i -ec`; confirm whether the GPU advertises Resizable BAR capability and which BAR sizes it supports.
- In Linux, capture `lspci -vv -s <GPU_BDF>`, `lspci -xxxx -s <GPU_BDF>`, and `dmesg | rg -i 'BAR|MMIO|resource|pci'`.
- In Windows, check Device Manager resources for `Large Memory` and GPU-Z/NVIDIA/AMD driver ReBAR status.
- Save current BIOS settings and NVRAM state before testing any setup-variable changes.
