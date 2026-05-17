#!/usr/bin/env python3
import struct

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print("快速搜索Setup相关FFS文件...")
    print(f"ROM大小: {len(data)} bytes")
    print()

    # 首先找到所有Setup字符串的位置
    setup_positions = []
    start = 0
    while True:
        idx = data.find(b'Setup', start)
        if idx == -1:
            break
        setup_positions.append(idx)
        start = idx + 1

    print(f"找到 {len(setup_positions)} 个'Setup'字符串")
    print()

    # 对于每个Setup位置，向前搜索FFS文件头
    found_ffs = {}
    for pos in setup_positions:
        # FFS文件头特征：16字节GUID + 1字节Type + 1字节Attributes + 3字节Size
        # 向前搜索最多1MB
        search_start = max(0, pos - 0x100000)
        for offset in range(search_start, pos - 23):
            # 快速检查：GUID不应该全0或全FF
            guid = data[offset:offset+16]
            if guid == b'\x00'*16 or guid == b'\xff'*16:
                continue
            # 检查文件类型
            ftype = data[offset+16]
            if ftype not in {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10}:
                continue
            # 读取文件大小
            size_raw = data[offset+18:offset+21]
            fsize = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
            if fsize < 0x100 or fsize > 0x400000:
                continue
            # 检查文件是否覆盖Setup字符串位置
            if offset + fsize > pos:
                guid_str = guid.hex()
                if guid_str not in found_ffs:
                    found_ffs[guid_str] = {
                        'offset': offset,
                        'type': ftype,
                        'size': fsize,
                        'guid': guid_str
                    }
                break

    print(f"找到 {len(found_ffs)} 个唯一的FFS文件:")
    print()

    for guid_str, ffs in found_ffs.items():
        type_names = {0x01:'RAW',0x02:'FreeForm',0x03:'SEC',0x04:'PEI',0x05:'DXE',0x06:'PEIM',0x07:'Driver',0x08:'App',0x09:'MM',0x0B:'PAD',0x0C:'PE32',0x0D:'PIC',0x0E:'TE',0x0F:'DXE_SMM',0x10:'User'}
        tname = type_names.get(ffs['type'], f"0x{ffs['type']:02x}")
        print(f"FFS @ 0x{ffs['offset']:08x}, 类型={tname}, 大小=0x{ffs['size']:06x} ({ffs['size']//1024}KB)")
        print(f"  GUID: {ffs['guid']}")

        # 提取文件数据并搜索关键字符串
        file_data = data[ffs['offset']:ffs['offset']+ffs['size']]

        keywords = [b'Setup', b'AMITSE', b'AMD CBS', b'AMD PBS', b'AMD Overclocking',
                    b'Advanced', b'Chipset', b'Main', b'Security', b'Boot', b'Exit',
                    b'Above 4G', b'Resizable', b'BAR', b'XMP', b'DOCP', b'SVM',
                    b'IOMMU', b'PBO', b'Overclock', b'Hidden', b'Suppress', b'GrayOut']

        found_keywords = []
        for kw in keywords:
            if kw in file_data:
                idx = file_data.find(kw)
                found_keywords.append((kw.decode(errors='replace'), idx))

        if found_keywords:
            print(f"  关键字符串:")
            for kw, idx in found_keywords:
                print(f"    {kw:20s} @ 0x{ffs['offset']+idx:08x}")
        print()

if __name__ == '__main__':
    main()
