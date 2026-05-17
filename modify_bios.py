#!/usr/bin/env python3
import struct
import os
import shutil

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"
OUTPUT_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C_modified.rom"

def copy_rom():
    """复制原始ROM作为修改基础"""
    shutil.copy2(ROM_PATH, OUTPUT_PATH)
    print(f"已复制原始ROM到: {OUTPUT_PATH}")

def read_rom():
    """读取ROM数据"""
    with open(OUTPUT_PATH, 'rb') as f:
        return bytearray(f.read())

def write_rom(data):
    """写回ROM数据"""
    with open(OUTPUT_PATH, 'wb') as f:
        f.write(data)

def find_setup_nvram_area(data):
    """找到Setup NVRAM变量的存储区域"""
    # Setup变量在偏移 0x370b2 和 0x10370b2 处有两个副本
    # 这是NVRAM存储区域，包含默认的Setup变量值
    positions = []
    start = 0
    while True:
        idx = data.find(b'Setup\x00', start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions

def analyze_setup_defaults(data, setup_offset):
    """分析Setup变量的默认值结构"""
    print(f"\n分析 Setup @ 0x{setup_offset:08x}:")

    # NVAR头结构:
    # 4字节签名 "NVAR"
    # 2字节大小
    # 2字节属性
    # 1字节命名空间
    # 然后变量名和数据

    # 向前搜索NVAR头
    search_start = max(0, setup_offset - 0x100)
    nvar_offset = None
    for i in range(search_start, setup_offset):
        if data[i:i+4] == b'NVAR':
            nvar_offset = i
            break

    if nvar_offset:
        nvar_size = struct.unpack('<H', data[nvar_offset+4:nvar_offset+6])[0]
        print(f"  NVAR头 @ 0x{nvar_offset:08x}, 大小={nvar_size}")

    # 显示Setup变量数据（假设是二进制标志位）
    setup_data_start = setup_offset + 6  # "Setup\x00" 之后
    setup_data = data[setup_data_start:setup_data_start+256]

    print(f"  Setup数据前64字节:")
    for i in range(0, min(64, len(setup_data)), 16):
        hex_str = ' '.join(f'{b:02x}' for b in setup_data[i:i+16])
        print(f"    0x{setup_data_start+i:08x}: {hex_str}")

    return setup_data_start

def find_menu_strings(data):
    """查找BIOS菜单相关的字符串"""
    menu_keywords = [
        b'Main', b'Advanced', b'Chipset', b'Security', b'Boot', b'Exit',
        b'CPU Configuration', b'Memory Configuration', b'PCIe Configuration',
        b'USB Configuration', b'SATA Configuration', b'NVMe Configuration',
        b'AMD CBS', b'AMD PBS', b'AMD Overclocking',
        b'Above 4G Decoding', b'Resizable BAR', b'Smart Access Memory',
        b'XMP', b'DOCP', b'EXPO', b'Memory Frequency',
        b'SVM Mode', b'AMD-V', b'IOMMU', b'SR-IOV',
        b'CSM', b'Legacy Support', b'UEFI Only',
        b'PBO', b'Precision Boost', b'Curve Optimizer',
        b'FCLK', b'MCLK', b'UCLK', b'Infinity Fabric'
    ]

    found = []
    for kw in menu_keywords:
        start = 0
        while True:
            idx = data.find(kw, start)
            if idx == -1:
                break
            found.append((kw.decode(errors='replace'), idx))
            start = idx + 1

    return found

def find_access_level_checks(data):
    """查找访问级别检查相关的代码模式"""
    # 在UEFI BIOS中，菜单项的显示通常由以下条件控制:
    # 1. SuppressIf 操作码 (0x5A)
    # 2. GrayOutIf 操作码 (0x5B)
    # 3. DisableIf 操作码 (0x5C)
    # 4. 访问级别检查

    checks = []

    # 搜索常见的条件跳转模式
    # ARM Thumb: CBZ/CBNZ 指令 (0xB1 xx)
    # 或者数据中的布尔标志

    # 搜索 "User" / "Supervisor" / "Admin" 字符串
    access_levels = [b'User', b'Supervisor', b'Administrator', b'Admin']
    for level in access_levels:
        start = 0
        while True:
            idx = data.find(level, start)
            if idx == -1:
                break
            checks.append((level.decode(), idx))
            start = idx + 1

    return checks

def modify_setup_defaults(data):
    """修改Setup变量的默认值以启用隐藏功能"""
    # 这是一个实验性的修改
    # 我们需要找到控制菜单显示的Setup变量位

    setup_positions = find_setup_nvram_area(data)
    print(f"找到 {len(setup_positions)} 个Setup变量位置")

    for pos in setup_positions:
        setup_data_start = analyze_setup_defaults(data, pos)

        # 这里我们需要知道哪些字节控制哪些功能
        # 由于我们没有完整的文档，这里做一些常见的修改尝试

        # 注意：这些偏移是猜测的，需要根据实际情况调整
        # 典型的Setup变量结构:
        # 偏移0x00-0x0F: 基本系统设置
        # 偏移0x10-0x1F: 高级CPU设置
        # 偏移0x20-0x2F: 内存设置
        # 偏移0x30-0x3F: PCIe/显卡设置
        # 偏移0x40-0x4F: 安全设置
        # 偏移0x50-0x5F: 启动设置

        print(f"  尝试修改Setup默认值...")

        # 尝试启用一些常见的隐藏选项
        # 这些修改基于常见的AMI BIOS Setup变量布局
        # 实际效果需要测试验证

        # 保存原始值用于比较
        original = bytes(data[setup_data_start:setup_data_start+64])

        # 尝试修改一些字节（这些是基于经验的猜测）
        # 偏移0x02: 可能控制高级菜单显示
        # 偏移0x04: 可能控制超频选项
        # 偏移0x08: 可能控制虚拟化选项
        # 偏移0x0C: 可能控制PCIe高级选项

        # 由于不确定具体含义，我们先不做实际修改
        # 而是输出建议的修改位置

        print(f"  原始数据: {original.hex()}")
        print(f"  建议: 需要进一步分析确定具体字节含义")

    return data

def add_menu_strings(data):
    """
    尝试在ROM中添加新的菜单字符串
    注意：这需要在有可用空间的地方添加，并更新引用
    """
    print("\n尝试添加新的菜单字符串...")

    # 找到字符串存储区域（通常在FFS文件的特定节中）
    # 我们需要找到有足够空闲空间的地方

    # 搜索全0区域作为潜在的插入点
    zero_runs = []
    i = 0
    while i < len(data) - 16:
        if data[i] == 0:
            start = i
            while i < len(data) and data[i] == 0:
                i += 1
            length = i - start
            if length >= 256:
                zero_runs.append((start, length))
        else:
            i += 1

    print(f"找到 {len(zero_runs)} 个大于256字节的零值区域")
    for start, length in zero_runs[:10]:
        print(f"  0x{start:08x} - 0x{start+length:08x} ({length} bytes)")

    return data

def find_pe32_images(data):
    """查找所有PE32/PE32+镜像"""
    pe_images = []
    offset = 0
    while offset < len(data) - 64:
        if data[offset:offset+2] == b'MZ':
            # 检查PE签名
            pe_offset = struct.unpack('<I', data[offset+60:offset+64])[0]
            if pe_offset > 0 and pe_offset < 0x1000 and offset + pe_offset + 4 <= len(data):
                if data[offset+pe_offset:offset+pe_offset+4] == b'PE\x00\x00':
                    # 读取COFF头获取镜像大小
                    num_sections = struct.unpack('<H', data[offset+pe_offset+6:offset+pe_offset+8])[0]
                    optional_header_size = struct.unpack('<H', data[offset+pe_offset+20:offset+pe_offset+22])[0]
                    # 估算镜像大小
                    estimated_size = pe_offset + 24 + optional_header_size + num_sections * 40 + 0x10000
                    pe_images.append({
                        'offset': offset,
                        'pe_offset': pe_offset,
                        'num_sections': num_sections,
                        'estimated_size': estimated_size
                    })
        offset += 1
    return pe_images

def main():
    print("=" * 60)
    print("BIOS修改工具")
    print("=" * 60)

    # 复制原始ROM
    copy_rom()

    # 读取数据
    data = read_rom()

    print(f"\nROM大小: {len(data)} bytes")

    # 1. 分析Setup变量
    print("\n" + "=" * 60)
    print("1. 分析Setup NVRAM变量")
    print("=" * 60)
    data = modify_setup_defaults(data)

    # 2. 搜索菜单字符串
    print("\n" + "=" * 60)
    print("2. 搜索BIOS菜单字符串")
    print("=" * 60)
    menu_strings = find_menu_strings(data)
    print(f"找到 {len(menu_strings)} 个菜单相关字符串")
    for name, offset in sorted(menu_strings, key=lambda x: x[1])[:50]:
        print(f"  {name:30s} @ 0x{offset:08x}")

    # 3. 搜索访问级别检查
    print("\n" + "=" * 60)
    print("3. 搜索访问级别控制")
    print("=" * 60)
    access_checks = find_access_level_checks(data)
    print(f"找到 {len(access_checks)} 个访问级别字符串")
    for name, offset in access_checks[:20]:
        print(f"  {name:20s} @ 0x{offset:08x}")

    # 4. 查找PE32镜像
    print("\n" + "=" * 60)
    print("4. 查找PE32/PE32+镜像")
    print("=" * 60)
    pe_images = find_pe32_images(data)
    print(f"找到 {len(pe_images)} 个PE32镜像")
    for pe in pe_images[:20]:
        print(f"  偏移=0x{pe['offset']:08x}, PE头=0x{pe['pe_offset']:04x}, 节数={pe['num_sections']}, 估计大小=0x{pe['estimated_size']:06x}")

    # 5. 查找可用空间
    print("\n" + "=" * 60)
    print("5. 查找可用空间")
    print("=" * 60)
    data = add_menu_strings(data)

    # 保存修改
    write_rom(data)
    print(f"\n已保存修改后的ROM到: {OUTPUT_PATH}")
    print("注意：当前尚未进行实际修改，仅完成了分析")

if __name__ == '__main__':
    main()
