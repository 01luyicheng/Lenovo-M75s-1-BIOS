# Lenovo M75s-1 BIOS 修改可行性分析

本仓库目前存放的是 Lenovo M75s-1 固件更新包，而非已解压的 UEFI 树。以下分析基于可启动 ISO 以及从中提取的 32 MiB `IMAGEM2C.ROM`。

## 源镜像

| 文件 | 大小 | SHA256 | 备注 |
| --- | ---: | --- | --- |
| `BIOS-M2CJY53USA.exe` | 19,331,608 字节 | `639bad1ea7ae2045af73388249ac9cd9525486ad0c93415037ded49b3d143bf6` | Windows 更新包；字符串显示为 Inno Setup 封装。 |
| `BIOSCD-M2CJ953USA.iso` | 100,726,784 字节 | `f7b6929fccde8f74efd4fb8bce44f375dd4569db6abd70005a46e643eed0ded4` | 可启动刷写 ISO；包含主 ROM 和 UEFI Shell 刷写镜像。 |

ISO 根目录包含以下载荷：

| ISO 载荷 | 大小 | SHA256 | 用途 |
| --- | ---: | --- | --- |
| `CHANGES.TXT` | 2,455 字节 | `1d61f5317f1e9c62d2fca1b26a31b6b86bbfd92797bf7c083be77086390e4791` | Lenovo 变更日志。 |
| `IMAGEM2C.ROM` | 33,554,432 字节 | `8fb2f1044a3d79320afa0e5efdcf3c868c6bf7d17064c868eb4ed811b6adf8e9` | 主 32 MiB UEFI/SPI 镜像，也是主要研究目标。 |
| `M2CJT53A.IMG` | 67,108,864 字节 | `4ca889d24405dc54ce007cddcbb0160e3a09fe599c930d93c86a0a56515df2a3` | FAT 格式的 UEFI Shell 刷写镜像。 |
| `README.TXT` | 12,503 字节 | `c425c10a087ec1fd717de871476a9ad3ace83af5f060164b408933bbfde357d9` | Lenovo 刷写和工具说明。 |

UEFI Shell 镜像包含 `STARTUP.NSH`、`FLASH2.EFI`、`AfuEfix64.efi`、`AMIDEEFIx64.efi`、logo 工具以及另一份 `IMAGEM2C.ROM` 副本。`STARTUP.NSH` 最终调用 `flash2.efi imageM2C.rom /bb /rsmb`；README 中说明了 `/rsmb`、`/clr`、`/ign`、`/quiet` 以及与密码相关的刷写选项。

## 轻量级检查辅助工具

`tools/inspect_bios.py` 被添加为一个可复现、无外部依赖的检查辅助工具。它仅使用 Python 标准库完成以下功能：

1. 解析 ISO9660 根目录；
2. 将 ISO 载荷默认提取到 `/tmp/lenovo_m75s_bios_extract`；
3. 计算 SHA256 哈希值；
4. 在 `IMAGEM2C.ROM` 中查找关键字符串；
5. 识别 `_FVH` 固件卷；
6. 遍历简单的 FFS 文件头，并报告其内容中包含 `Setup`、`AMITSE`、`Above 4G`、`CBS`、`NBIO`、`IOMMU` 和 `PCI` 等关键词的文件。

该辅助工具**不能替代** UEFITool NE、UEFIExtract、IFRExtractor、AMITSE 解析器或反汇编器。其目的是在此最小化环境中实现首轮证据收集的可复现性。

## UEFI 固件卷布局

32 MiB 的 `IMAGEM2C.ROM` 包含多个有效的 UEFI 固件卷：

| FV 基址 | 长度 | 备注 |
| ---: | ---: | --- |
| `0x00000000` | `0x20000` | 固件卷。 |
| `0x00037000` | `0x20000` | NVRAM/变量区域候选。 |
| `0x00077000` | `0x20000` | 固件卷。 |
| `0x006cf000` | `0x631000` | 大型固件卷 / 封装内容候选。 |
| `0x006e1488` | `0x20000` | 嵌入式固件卷。 |
| `0x00d00000` | `0x300000` | AMD/PEI 平台模块集中于此。 |
| `0x01000000` | `0x20000` | 固件卷。 |
| `0x01037000` | `0x20000` | 镜像/冗余的 NVRAM/变量区域候选。 |
| `0x01077000` | `0x20000` | 固件卷。 |
| `0x01411000` | `0x8ef000` | 大型固件卷 / 备用镜像区域。 |
| `0x01423488` | `0x20000` | 嵌入式固件卷。 |
| `0x01d00000` | `0x300000` | 大型 FFS 数据块。 |
| `0x01d02000` | `0x2fe000` | AMD/PEI 平台模块。 |

两个看起来重复的 `0x00037000` 和 `0x01037000` 区域都包含 `AMITSESetup`、`Setup` 及相关变量名称，因此在完整的 NVAR 解析器确认其确切作用之前，可将其视为镜像/冗余的变量/默认存储证据。

## Setup、AMITSE 与 NVRAM 证据

ROM 中包含 AMI 设置相关的 NVAR 名称及短变量载荷。重要发现如下：

| 变量/字符串 | 近似 ROM 证据位置 | 当前解读 |
| --- | --- | --- |
| `StdDefaults` | 约 `0x00037090` 和 `0x01037090` | 默认变量块证据。 |
| `Setup` | 约 `0x000370a7` 和 `0x010370a7`；数据区域始于约 `0x000370b8` / `0x010370b8`，长度约 `0x20d` | 主 BIOS 设置变量可能存在，但若无 IFR 则无法确定其内部偏移。 |
| `AMITSESetup` | 约 `0x000372f8` 和 `0x010372f8`；数据区域始于约 `0x0003730f` / `0x0103730f`，长度约 `0x183` | AMI TSE/设置 UI 状态变量候选。 |
| `SecureBootSetup` | 约 `0x000375f1` 和 `0x010375f1`；载荷疑似为 `01 01 01 00 00 00 00` | Secure Boot 设置状态变量候选；并非完整的 Secure Boot 密钥/状态模型。 |
| `ROM_CMN` | 约 `0x00037613` 和 `0x01037613`，长度约 `0xfc` | 平台通用设置状态候选。 |
| `PCI_COMMON` | 约 `0x00037722` 和 `0x01037722`，长度约 `0x7`，默认字节全为零 | PCI 相关设置状态候选；字段含义若无 IFR 或逆向工程则未知。 |

**严禁**将上述 ROM 偏移量直接用作 `setup_var` 的偏移量。`setup_var` 需要 IFR 的 `VarStore` 和问题项（question）的 `VarOffset` 信息，而上述偏移量仅为 NVAR/默认存储区域在闪存镜像中的位置。

## 隐藏设置与 XMP 评估

现有证据**无法证明** XMP/A-XMP 或完整的 AMD CBS/PBS 设置页面已存在但被隐藏。

发现：

- `Setup` 和 `AMITSESetup` 变量存在。
- CBS 相关平台模块和字符串存在，包括 `CbsBasePeiZP`、`CbsBasePeiRV`、`CbsBasePeiSSP` 和 `FchPromontoryCbsPei` 风格的证据。
- NBIO、IOMMU、GNB、PCIe 和内存初始化模块存在。
- 直接可读的字符串**未**显示清晰的 `AMD CBS`、`AMD PBS`、`A-XMP`、`D.O.C.P.`、`Memory Profile` 或 XMP 设置菜单文本。
- 原始 `XMP` 字节序列可能出现在大型二进制数据块内部，但没有可读的 HII/IFR 菜单证据将其与用户可见选项关联。

实践结论：XMP 目前尚不适合作为"简单取消隐藏即可启用"的目标。

如果后续的 IFR 提取发现了 XMP/DRAM 相关问题项（question），可以将其映射到 `Setup`/AMD 设置变量偏移。如果 IFR 中没有此类问题项（question），则 XMP 需要 AGESA/内存策略层面的工作，或 HII/菜单移植。这将带来显著更高的风险。

## Resizable BAR / Above 4G 评估

### 已存在的内容

固件包含 PCIe 和 64 位 MMIO 资源处理的底层证据：

- `Above 4G` 字符串存在，包括关于 `Above 4G MMIO base`、缺少 4G 以上 MMIO 空间，以及用户请求 4G 以上可预取 MMIO 大小/对齐的消息。
- NBIO/GNB/PCIe 模块存在，包括 `AmdNbioPcie*Pei` 和 `GnbSetTom*` 风格的证据。
- 资源分配字符串存在，包括 TOM/TOM2、PCIe 配置空间、每个根桥资源大小，以及 4G 以上可预取/不可预取 MMIO 分配。
- UEFI Shell PCI 诊断文本包含 Resizable BAR 能力字符串，如 `Resizeable Bar Capability`（固件中原文拼写如此）、`ResizableBarCapability` 和 `ResizableBarControl`。

### 目前尚未证实的内容

当前镜像**未**显示用户可见或策略层面的 ReBAR 实现的清晰证据：

- 无清晰的 `Re-Size BAR Support` 设置字符串；
- 无清晰的 `Resizable BAR` 设置字符串；
- 无清晰的 `Smart Access Memory` 设置字符串；
- 无已证实的 ReBAR IFR 问题或设置变量；
- 无已证实的 DXE 策略在 PCI 资源分配前选择 GPU BAR 大小。

UEFI Shell 中的 PCI 字符串仅表明 Shell 能够解码 PCIe Resizable BAR 扩展能力。这并不意味着平台固件启用了 GPU ReBAR。

### 可行性结论

添加真正的 Resizable BAR 支持很可能不仅仅是菜单解锁的改动。一个可用的实现通常需要以下全部条件：

1. CSM 禁用，且使用支持 UEFI GOP 的 GPU 启动。
2. Above 4G / 大型 64 位可预取 MMIO 地址窗口。
3. PCI 主桥和 PciBus 资源分配能够分配非常大的 GPU BAR。
4. 策略代码扫描 PCIe 扩展能力 ID `0x15`，选择支持的 BAR 大小，写入 Resizable BAR 控制寄存器，且时机需足够早，以便后续进行 PCI 资源大小调整。
5. ACPI 根桥资源与分配的大型 BAR 保持一致。
6. GPU VBIOS 和操作系统/驱动支持。

因此，建议的步骤是首先证明或启用 Above 4G 资源分配，然后确定是否存在任何隐藏的 ReBAR 策略。如果不存在 ReBAR 策略，下一步是与另一款已支持 ReBAR 的类似 Lenovo/AMI AM4 BIOS 进行二进制对比。

## 推荐的后续工作

1. 使用 UEFITool NE 或 UEFIExtract 打开 `IMAGEM2C.ROM`，并递归提取压缩/封装过的段。
2. 定位 `Setup`、`AMITSE`、HII 包列表以及任何 SetupUtility 风格的模块。
3. 在每个候选 PE32/HII 二进制主体上运行 IFRExtractor 或 ifrextract-rs。
4. 在 IFR 输出中搜索 `AMD CBS`、`AMD PBS`、`CBS`、`NBIO`、`IOMMU`、`Above 4G`、`PCIe`、`XMP`、`A-XMP`、`DRAM Timing`、`Memory Frequency`、`CSM` 和 `Secure Boot`。
5. 如果找到问题项（question），在尝试 `setup_var` 之前，记录 `VarStore`、`VarStoreId`、`QuestionId`、`VarOffset`、宽度、默认值以及任何 `SuppressIf` 或 `GrayOutIf` 条件。
6. 如果未找到目标功能对应的问题项（question），请将其视为策略/HII 移植或 DXE/AGESA 逆向工程任务，而非简单的设置解锁。
7. 在刷写任何修改后的 ROM 之前，进行完整的外部 SPI 转储，并准备好硬件恢复方案。

## 基线验证建议

在进行任何修改之前，记录硬件基线：

- 在 UEFI Shell 中，使用 `pci` 和 `pci <bus> <dev> <fn> -i -ec` 检查 GPU 和根端口；确认 GPU 是否宣告 Resizable BAR 能力以及支持哪些 BAR 大小。
- 在 Linux 中，捕获 `lspci -vv -s <GPU_BDF>`、`lspci -xxxx -s <GPU_BDF>` 和 `dmesg | rg -i 'BAR|MMIO|resource|pci'`。
- 在 Windows 中，检查设备管理器资源中的 `Large Memory` 以及 GPU-Z/NVIDIA/AMD 驱动的 ReBAR 状态。
- 在测试任何设置变量更改之前，保存当前 BIOS 设置和 NVRAM 状态。
