#!/usr/bin/env python3
import struct

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def find_all_ffs_files(data):
    """全局搜索FFS文件头"""
    files = []
    offset = 0
    while offset + 24 <= len(data):
        # FFS文件头格式：16字节GUID + 1字节Type + 1字节Attributes + 3字节Size + 1字节State
        file_guid = data[offset:offset+16]
        # 跳过全0或全FF
        if file_guid == b'\x00' * 16 or file_guid == b'\xff' * 16:
            offset += 1
            continue
        # 检查GUID是否合理（不是所有字节都相同）
        if len(set(file_guid)) == 1:
            offset += 1
            continue
        file_type = data[offset+16]
        # 常见有效的文件类型
        valid_types = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0xF0}
        if file_type not in valid_types:
            offset += 1
            continue
        size_raw = data[offset+18:offset+21]
        file_size = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
        if file_size < 24 or file_size > 0x200000:
            offset += 1
            continue
        # 检查state字节
        state = data[offset+23]
        if state not in {0x00, 0x01, 0x07, 0xF8}:
            offset += 1
            continue
        # 额外检查：GUID前几个字节不应该都是0
        if file_guid[0:4] == b'\x00\x00\x00\x00':
            offset += 1
            continue
        files.append({
            'offset': offset,
            'type': file_type,
            'size': file_size,
            'guid': file_guid.hex()
        })
        offset += file_size
        if file_size == 0:
            offset += 1
    return files

def extract_section_data(data, ffs_offset, ffs_size):
    """提取FFS文件中的节数据"""
    # 跳过FFS头(24字节)，然后解析节
    sec_offset = ffs_offset + 24
    sections = []
    while sec_offset < ffs_offset + ffs_size:
        if sec_offset + 4 > len(data):
            break
        sec_size = struct.unpack('<I', data[sec_offset:sec_offset+4])[0] & 0x00FFFFFF
        sec_type = data[sec_offset+3]
        if sec_size == 0 or sec_size > ffs_size:
            break
        sections.append({
            'offset': sec_offset,
            'type': sec_type,
            'size': sec_size,
            'data': data[sec_offset+4:sec_offset+sec_size]
        })
        sec_offset += sec_size
        sec_offset = (sec_offset + 3) & ~3
    return sections

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print("搜索包含Setup字符串的FFS文件...")
    print()

    # 先找到所有包含"Setup"字符串的位置
    setup_positions = []
    start = 0
    while True:
        idx = data.find(b'Setup', start)
        if idx == -1:
            break
        setup_positions.append(idx)
        start = idx + 1

    print(f"找到 {len(setup_positions)} 个'Setup'字符串出现位置")
    print()

    # 对于每个Setup位置，尝试找到包含它的FFS文件
    for pos in setup_positions[:20]:
        # 向前搜索FFS头
        search_start = max(0, pos - 0x100000)
        found_ffs = None
        for offset in range(search_start, pos):
            file_guid = data[offset:offset+16]
            if file_guid == b'\x00' * 16 or file_guid == b'\xff' * 16:
                continue
            if len(set(file_guid)) == 1:
                continue
            file_type = data[offset+16]
            valid_types = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0xF0}
            if file_type not in valid_types:
                continue
            size_raw = data[offset+18:offset+21]
            file_size = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
            if file_size < 24 or file_size > 0x200000:
                continue
            if offset + file_size > pos:
                found_ffs = {'offset': offset, 'type': file_type, 'size': file_size, 'guid': file_guid.hex()}
                break
        if found_ffs:
            type_names = {0x01:'RAW',0x02:'FreeForm',0x03:'SEC',0x04:'PEI',0x05:'DXE',0x06:'PEIM',0x07:'Driver',0x08:'App',0x09:'MM',0x0B:'PAD',0x0C:'PE32',0x0D:'PIC',0x0E:'TE',0x0F:'DXE_SMM',0x10:'User'}
            tname = type_names.get(found_ffs['type'], f"0x{found_ffs['type']:02x}")
            print(f"Setup @ 0x{pos:08x} -> FFS文件 @ 0x{found_ffs['offset']:08x}, 类型={tname}, 大小=0x{found_ffs['size']:06x}")
            print(f"  GUID: {found_ffs['guid']}")
            # 提取节信息
            sections = extract_section_data(data, found_ffs['offset'], found_ffs['size'])
            for sec in sections[:5]:
                sec_type_names = {0x01:'Compression',0x02:'GUID Defined',0x10:'PE32',0x11:'Pic',0x12:'Te',0x13:'DXE_DEPEX',0x14:'Version',0x15:'User Interface',0x16:'Compatibility',0x17:'Firmware Volume Image',0x18:'Freeform Subtype GUID',0x19:'Raw',0x1B:'PEI_DEPEX',0x1C:'MM_DEPEX'}
                stname = sec_type_names.get(sec['type'], f"0x{sec['type']:02x}")
                print(f"    节: 类型={stname}, 偏移=0x{sec['offset']:08x}, 大小=0x{sec['size']:06x}")
            print()

if __name__ == '__main__':
    main()
