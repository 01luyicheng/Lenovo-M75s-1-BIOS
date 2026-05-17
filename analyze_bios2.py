#!/usr/bin/env python3
import struct

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def find_fv_headers(data):
    """查找所有UEFI Firmware Volume头 - 使用正确的签名位置"""
    signature = b'_FVH'
    offsets = []
    start = 0
    while True:
        idx = data.find(signature, start)
        if idx == -1:
            break
        # _FVH签名位于偏移40处，所以FV头起始位置是 idx - 40
        fv_start = idx - 40
        if fv_start >= 0:
            offsets.append(fv_start)
        start = idx + 1
    return offsets

def parse_fv_header(data, offset):
    """解析FV头基本信息"""
    if offset < 0 or offset + 56 > len(data):
        return None
    zero_vector = data[offset:offset+16]
    file_system_guid = data[offset+16:offset+32]
    fv_length = struct.unpack('<Q', data[offset+32:offset+40])[0]
    signature = data[offset+40:offset+44]
    attributes = struct.unpack('<I', data[offset+44:offset+48])[0]
    header_length = struct.unpack('<H', data[offset+48:offset+50])[0]
    checksum = struct.unpack('<H', data[offset+50:offset+52])[0]
    ext_header_offset = struct.unpack('<H', data[offset+52:offset+54])[0]
    # 验证签名
    if signature != b'_FVH':
        return None
    # 验证大小合理性
    if fv_length == 0 or fv_length > 0x2000000 or fv_length < 0x1000:
        return None
    return {
        'offset': offset,
        'fv_length': fv_length,
        'signature': signature,
        'attributes': attributes,
        'header_length': header_length,
        'checksum': checksum,
        'ext_header_offset': ext_header_offset,
        'end': offset + fv_length
    }

def find_files_in_fv(data, fv_offset, fv_end):
    """在FV中查找文件头"""
    files = []
    # 先读取FV头长度
    hdr_len = struct.unpack('<H', data[fv_offset+48:fv_offset+50])[0]
    offset = fv_offset + hdr_len
    # 对齐到8字节
    offset = (offset + 7) & ~7
    while offset + 24 <= min(fv_end, len(data)):
        file_guid = data[offset:offset+16]
        if file_guid == b'\xff' * 16:
            break
        file_type = data[offset+16]
        # 文件大小在偏移18-21，3字节
        size_raw = data[offset+18:offset+21]
        file_size = size_raw[0] | (size_raw[1] << 8) | (size_raw[2] << 16)
        state = data[offset+23]
        if file_size == 0 or file_size > fv_end - fv_offset:
            break
        files.append({
            'offset': offset,
            'type': file_type,
            'size': file_size,
            'guid': file_guid.hex()
        })
        offset += file_size
        offset = (offset + 7) & ~7
        if offset >= min(fv_end, len(data)):
            break
    return files

def find_setup_modules(data):
    """查找Setup相关模块 - 搜索FFS文件中的PE32节"""
    keywords = [b'Setup', b'AMITSE', b'SetupBrowser', b'SetupUtility', b'SetupData',
                b'AMD CBS', b'AMD PBS', b'AMD Overclocking', b'AMD Common',
                b'Advanced', b'Chipset', b'Main', b'Security', b'Boot', b'Exit']
    results = []
    for kw in keywords:
        start = 0
        while True:
            idx = data.find(kw, start)
            if idx == -1:
                break
            results.append((kw.decode(errors='replace'), idx))
            start = idx + 1
    return results

def find_pe32_sections(data, fv_offset, fv_end):
    """在FV中查找PE32/PE32+镜像"""
    pe_signatures = []
    start = fv_offset
    while True:
        idx = data.find(b'MZ', start)
        if idx == -1 or idx >= min(fv_end, len(data)) - 64:
            break
        # 检查PE签名
        pe_offset_raw = data[idx+60:idx+64]
        if len(pe_offset_raw) < 4:
            break
        pe_offset = struct.unpack('<I', pe_offset_raw)[0]
        if pe_offset > 0 and pe_offset < 0x1000 and idx + pe_offset + 4 <= len(data):
            if data[idx+pe_offset:idx+pe_offset+4] in [b'PE\x00\x00', b'PE\x00\x00']:
                pe_signatures.append(idx)
        start = idx + 2
    return pe_signatures

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print(f"ROM大小: {len(data)} bytes ({len(data)//1024//1024} MB)")
    print()

    fv_offsets = find_fv_headers(data)
    valid_fvs = []
    for fv_off in fv_offsets:
        hdr = parse_fv_header(data, fv_off)
        if hdr:
            valid_fvs.append(hdr)

    print(f"找到 {len(valid_fvs)} 个有效的Firmware Volume")
    print()

    for i, hdr in enumerate(valid_fvs):
        print(f"FV #{i}: 偏移=0x{hdr['offset']:08x}, 大小=0x{hdr['fv_length']:08x} ({hdr['fv_length']//1024}KB), 头长度={hdr['header_length']}, 结束=0x{hdr['end']:08x}")
        files = find_files_in_fv(data, hdr['offset'], hdr['end'])
        print(f"  FFS文件数量: {len(files)}")
        for f in files[:5]:
            type_names = {0x00:'ALL',0x01:'RAW',0x02:'FreeForm',0x03:'SEC',0x04:'PEI',0x05:'DXE',0x06:'PEIM',0x07:'Driver',0x08:'App',0x09:'MM',0x0A:'FV',0x0B:'PAD',0x0C:'PE32',0x0D:'PIC',0x0E:'TE',0x0F:'DXE_SMM'}
            tname = type_names.get(f['type'], f"0x{f['type']:02x}")
            print(f"    偏移=0x{f['offset']:08x} 类型={tname} 大小=0x{f['size']:06x} GUID={f['guid']}")
        if len(files) > 5:
            print(f"    ... 还有 {len(files)-5} 个文件")

        # 查找PE32镜像
        pe_sigs = find_pe32_sections(data, hdr['offset'], hdr['end'])
        if pe_sigs:
            print(f"  PE32镜像数量: {len(pe_sigs)}")
        print()

    print("="*60)
    print("查找Setup/菜单相关字符串位置 (前50个):")
    setup_results = find_setup_modules(data)
    seen = set()
    count = 0
    for name, offset in setup_results:
        key = (name, offset)
        if key not in seen:
            seen.add(key)
            print(f"  {name:20s} @ 0x{offset:08x}")
            count += 1
            if count >= 50:
                break

if __name__ == '__main__':
    main()
