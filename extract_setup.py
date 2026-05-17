#!/usr/bin/env python3
import struct
import zlib
import lzma

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def find_compressed_sections(data, start_offset, end_offset):
    """搜索压缩节"""
    results = []
    offset = start_offset
    while offset < end_offset - 4:
        # 检查常见的压缩签名
        # LZMA: 5D 00 00 80 00 (LZMA属性)
        if data[offset:offset+5] == b'\x5d\x00\x00\x80\x00':
            results.append(('LZMA', offset))
        # 或者检查节头中的压缩类型
        offset += 1
    return results

def decompress_lzma(data):
    """尝试解压LZMA数据"""
    try:
        # LZMA格式需要添加头部
        # 标准LZMA头部: 属性(5字节) + 字典大小(4字节) + 未压缩大小(8字节)
        # 但UEFI通常使用简化格式
        decompressed = lzma.decompress(data)
        return decompressed
    except Exception as e:
        return None

def find_setup_ffs(data):
    """更精确地查找Setup相关的FFS文件"""
    results = []
    offset = 0
    while offset + 24 <= len(data):
        file_guid = data[offset:offset+16]
        # 检查是否是有效的GUID格式
        if file_guid == b'\x00' * 16 or file_guid == b'\xff' * 16:
            offset += 1
            continue
        # 跳过全相同字节的GUID
        if len(set(file_guid)) == 1:
            offset += 1
            continue
        file_type = data[offset+16]
        # 有效的文件类型范围
        if file_type > 0x20 and file_type not in {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF}:
            offset += 1
            continue
        size_raw = data[offset+18:offset+21]
        file_size = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
        if file_size < 24 or file_size > 0x400000:  # 最大4MB
            offset += 1
            continue
        # 检查文件内容是否包含Setup字符串
        file_end = min(offset + file_size, len(data))
        file_data = data[offset:file_end]
        if b'Setup' in file_data or b'AMITSE' in file_data or b'AMD CBS' in file_data or b'AMD PBS' in file_data:
            results.append({
                'offset': offset,
                'type': file_type,
                'size': file_size,
                'guid': file_guid.hex(),
                'data': file_data
            })
        offset += 1
    return results

def extract_ifr_strings(data):
    """从IFR二进制数据中提取字符串"""
    strings = []
    # IFR字符串通常以Unicode或ASCII形式存储
    # 搜索常见的IFR操作码
    # 0x5C = EFI_IFR_STRING_OP
    # 0x5D = EFI_IFR_REFRESH_OP
    # 0x5E = EFI_IFR_WARNING_IF_OP
    # 等等
    return strings

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print("搜索包含Setup/AMITSE/AMD CBS/AMD PBS的FFS文件...")
    print()

    setup_files = find_setup_ffs(data)
    print(f"找到 {len(setup_files)} 个相关FFS文件")
    print()

    for i, ffs in enumerate(setup_files):
        type_names = {0x01:'RAW',0x02:'FreeForm',0x03:'SEC',0x04:'PEI',0x05:'DXE',0x06:'PEIM',0x07:'Driver',0x08:'App',0x09:'MM',0x0B:'PAD',0x0C:'PE32',0x0D:'PIC',0x0E:'TE',0x0F:'DXE_SMM',0x10:'User'}
        tname = type_names.get(ffs['type'], f"0x{ffs['type']:02x}")
        print(f"文件 #{i}: 偏移=0x{ffs['offset']:08x}, 类型={tname}, 大小=0x{ffs['size']:06x}")
        print(f"  GUID: {ffs['guid']}")

        # 搜索文件中的关键字符串
        fd = ffs['data']
        keywords = [b'Setup', b'AMITSE', b'AMD CBS', b'AMD PBS', b'AMD Overclocking',
                    b'Advanced', b'Chipset', b'Main', b'Security', b'Boot', b'Exit',
                    b'Above 4G', b'Resizable', b'BAR', b'XMP', b'DOCP', b'SVM',
                    b'IOMMU', b'PBO', b'Overclock', b'Hidden', b'Suppress']
        found = []
        for kw in keywords:
            if kw in fd:
                # 找到所有出现位置
                start = 0
                while True:
                    idx = fd.find(kw, start)
                    if idx == -1:
                        break
                    found.append((kw.decode(errors='replace'), idx))
                    start = idx + 1

        if found:
            print(f"  找到的字符串 ({len(found)}个):")
            for kw, pos in found[:20]:
                print(f"    {kw:20s} @ 文件内偏移0x{pos:06x} (ROM偏移0x{ffs['offset']+pos:08x})")
            if len(found) > 20:
                print(f"    ... 还有 {len(found)-20} 个")
        print()

if __name__ == '__main__':
    main()
