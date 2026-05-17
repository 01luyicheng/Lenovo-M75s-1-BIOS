#!/usr/bin/env python3
import sys
import struct
import os

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def find_fv_headers(data):
    """查找所有UEFI Firmware Volume头"""
    signature = b'_FVH'
    offsets = []
    start = 0
    while True:
        idx = data.find(signature, start)
        if idx == -1:
            break
        offsets.append(idx - 16)  # FVH头在签名前16字节
        start = idx + 1
    return offsets

def parse_fv_header(data, offset):
    """解析FV头基本信息"""
    if offset < 0 or offset + 48 > len(data):
        return None
    zero_vector = data[offset:offset+16]
    file_system_guid = data[offset+16:offset+32]
    fv_length = struct.unpack('<Q', data[offset+32:offset+40])[0]
    signature = data[offset+40:offset+44]
    attributes = struct.unpack('<I', data[offset+44:offset+48])[0]
    return {
        'offset': offset,
        'fv_length': fv_length,
        'signature': signature,
        'attributes': attributes,
        'end': offset + fv_length
    }

def find_files_in_fv(data, fv_offset, fv_end):
    """在FV中查找文件头"""
    files = []
    offset = fv_offset + 48
    # 对齐到8字节
    offset = (offset + 7) & ~7
    while offset + 24 <= fv_end:
        file_guid = data[offset:offset+16]
        if file_guid == b'\xff' * 16:
            break
        file_type = data[offset+16]
        # 文件类型常见值: 0x01=RAW, 0x02=FreeForm, 0x03=SEC, 0x04=PEI, 0x05=DXE, 0x06=PEIM, 0x07=Driver, 0x08=Application, 0x09=MM, 0x0B=FFS_PAD
        files.append({
            'offset': offset,
            'type': file_type,
            'guid': file_guid.hex()
        })
        # 文件大小在偏移18-21，3字节
        size_raw = data[offset+18:offset+21]
        file_size = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
        if file_size == 0:
            break
        offset += file_size
        offset = (offset + 7) & ~7
        if offset >= fv_end:
            break
    return files

def find_setup_related(data):
    """查找Setup相关模块"""
    keywords = [b'Setup', b'AMITSE', b'SetupBrowser', b'SetupUtility', b'SetupData']
    results = []
    for kw in keywords:
        start = 0
        while True:
            idx = data.find(kw, start)
            if idx == -1:
                break
            # 找到包含这个字符串的FV
            results.append((kw.decode(), idx))
            start = idx + 1
    return results

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print(f"ROM大小: {len(data)} bytes ({len(data)//1024//1024} MB)")
    print()

    fv_offsets = find_fv_headers(data)
    print(f"找到 {len(fv_offsets)} 个Firmware Volume头")
    print()

    for i, fv_off in enumerate(fv_offsets):
        hdr = parse_fv_header(data, fv_off)
        if hdr:
            print(f"FV #{i}: 偏移=0x{fv_off:08x}, 大小=0x{hdr['fv_length']:08x} ({hdr['fv_length']//1024}KB), 结束=0x{hdr['end']:08x}")
            files = find_files_in_fv(data, fv_off, hdr['end'])
            print(f"  文件数量: {len(files)}")
            for f in files[:10]:
                type_names = {0x01:'RAW',0x02:'FreeForm',0x03:'SEC',0x04:'PEI',0x05:'DXE',0x06:'PEIM',0x07:'Driver',0x08:'App',0x09:'MM',0x0B:'PAD'}
                tname = type_names.get(f['type'], f"0x{f['type']:02x}")
                print(f"    偏移=0x{f['offset']:08x} 类型={tname} GUID={f['guid']}")
            if len(files) > 10:
                print(f"    ... 还有 {len(files)-10} 个文件")
            print()

    print("="*60)
    print("查找Setup相关字符串位置:")
    setup_results = find_setup_related(data)
    for name, offset in setup_results[:30]:
        print(f"  {name} @ 0x{offset:08x}")

if __name__ == '__main__':
    main()
