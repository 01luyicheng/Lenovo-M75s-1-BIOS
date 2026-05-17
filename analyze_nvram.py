#!/usr/bin/env python3
import struct

ROM_PATH = "/workspace/bios_extracted/code$GetExtractPath$/IMAGEM2C.rom"

def find_nvram_vars(data):
    """搜索NVRAM变量存储区域"""
    # AMI BIOS NVRAM通常在特定区域
    # 搜索常见的变量名
    var_names = [b'Setup', b'AMITSESetup', b'SecureBootSetup', b'BootOrder',
                 b'BootOption', b'ConIn', b'ConOut', b'ErrOut',
                 b'PlatformLang', b'OsIndications', b'BootCurrent',
                 b'BootNext', b'Timeout', b'ResetSystem']

    results = []
    for var_name in var_names:
        start = 0
        while True:
            idx = data.find(var_name, start)
            if idx == -1:
                break
            # 检查前后是否有GUID或长度字段
            results.append((var_name.decode(), idx))
            start = idx + 1
    return results

def find_ifr_opcodes(data):
    """搜索IFR操作码序列"""
    # IFR操作码常见值:
    # 0x01 = FORM_SET
    # 0x02 = FORM
    # 0x03 = STATEMENT
    # 0x05 = SUBTITLE
    # 0x06 = TEXT
    # 0x07 = REFERENCE
    # 0x08 = CROSS_REFERENCE
    # 0x09 = ONE_OF
    # 0x0A = CHECKBOX
    # 0x0B = NUMERIC
    # 0x0C = STRING
    # 0x0D = ONE_OF_OPTION
    # 0x0E = ORDERED_LIST
    # 0x1E = GUID
    # 0x5A = SUPPRESS_IF
    # 0x5B = GRAY_OUT_IF
    # 0x5C = STRING
    # 0x5E = WARNING_IF
    # 0x61 = NO_SUBMIT_IF
    # 0x62 = INCONSISTENT_IF
    # 0x86 = END

    # 搜索IFR操作码序列特征
    ifr_sequences = []

    # 搜索FORM_SET操作码 (0x01 0x86 ...)
    offset = 0
    while offset < len(data) - 8:
        # 检查是否是IFR操作码序列的开始
        # IFR操作码通常以0x01 (FORM_SET) 或 0x02 (FORM) 开始
        if data[offset] in [0x01, 0x02] and data[offset+1] == 0x86:
            ifr_sequences.append(('FORM_SET/FORM', offset))
        elif data[offset] == 0x5A and data[offset+1] == 0x86:
            ifr_sequences.append(('SUPPRESS_IF', offset))
        elif data[offset] == 0x5B and data[offset+1] == 0x86:
            ifr_sequences.append(('GRAY_OUT_IF', offset))
        offset += 1

    return ifr_sequences

def extract_string_package(data, offset, max_size=0x10000):
    """提取字符串包"""
    strings = []
    # 搜索Unicode字符串
    i = offset
    end = min(offset + max_size, len(data))
    while i < end - 2:
        # 检查是否是可打印的ASCII/Unicode字符串
        if 0x20 <= data[i] <= 0x7E:
            # 检查是否是ASCII字符串
            j = i
            while j < end and 0x20 <= data[j] <= 0x7E:
                j += 1
            if j - i >= 4:
                s = data[i:j].decode('ascii', errors='replace')
                strings.append((i, s))
                i = j
                continue
        i += 1
    return strings

def main():
    with open(ROM_PATH, 'rb') as f:
        data = f.read()

    print("=" * 60)
    print("NVRAM变量搜索")
    print("=" * 60)
    nvram_vars = find_nvram_vars(data)
    print(f"找到 {len(nvram_vars)} 个NVRAM变量引用")
    for name, offset in nvram_vars[:30]:
        print(f"  {name:25s} @ 0x{offset:08x}")
    print()

    print("=" * 60)
    print("搜索Setup字符串附近的二进制结构")
    print("=" * 60)

    # 找到Setup字符串的位置，分析其周围的二进制结构
    setup_positions = []
    start = 0
    while True:
        idx = data.find(b'Setup', start)
        if idx == -1:
            break
        setup_positions.append(idx)
        start = idx + 1

    for pos in setup_positions[:5]:
        print(f"\nSetup @ 0x{pos:08x}:")
        # 显示前后64字节的十六进制
        start = max(0, pos - 64)
        end = min(len(data), pos + 64)
        chunk = data[start:end]
        for i in range(0, len(chunk), 16):
            hex_str = ' '.join(f'{b:02x}' for b in chunk[i:i+16])
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk[i:i+16])
            print(f"  0x{start+i:08x}: {hex_str:<48s} {ascii_str}")

    print()
    print("=" * 60)
    print("搜索可能的菜单项隐藏标志")
    print("=" * 60)

    # 搜索SuppressIf和GrayOutIf操作码
    # 在UEFI IFR中，这些操作码控制菜单项的显示
    suppress_positions = []
    start = 0
    while True:
        idx = data.find(b'Suppress', start)
        if idx == -1:
            break
        suppress_positions.append(idx)
        start = idx + 1

    gray_positions = []
    start = 0
    while True:
        idx = data.find(b'Gray', start)
        if idx == -1:
            break
        gray_positions.append(idx)
        start = idx + 1

    hidden_positions = []
    start = 0
    while True:
        idx = data.find(b'Hidden', start)
        if idx == -1:
            break
        hidden_positions.append(idx)
        start = idx + 1

    print(f"Suppress: {len(suppress_positions)} 个")
    print(f"Gray: {len(gray_positions)} 个")
    print(f"Hidden: {len(hidden_positions)} 个")

    for pos in suppress_positions[:10]:
        print(f"  Suppress @ 0x{pos:08x}")
    for pos in gray_positions[:10]:
        print(f"  Gray @ 0x{pos:08x}")
    for pos in hidden_positions[:10]:
        print(f"  Hidden @ 0x{pos:08x}")

if __name__ == '__main__':
    main()
