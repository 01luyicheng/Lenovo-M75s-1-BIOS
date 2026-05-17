#!/usr/bin/env python3
"""
Generate final BIOS analysis report
"""

import json
import os

RESULTS_PATH = "/workspace/bios_analysis/analysis_results.json"
EXTRACTED_DIR = "/workspace/bios_analysis/extracted"

def load_results():
    with open(RESULTS_PATH, 'r') as f:
        return json.load(f)

def get_file_size(path):
    try:
        return os.path.getsize(path)
    except:
        return 0

def generate_report():
    results = load_results()
    
    print("=" * 80)
    print("UEFI BIOS 固件分析报告 - IMAGEM2C.rom")
    print("=" * 80)
    print(f"\n固件文件: {results['file']}")
    print(f"文件大小: {results['size']:,} bytes ({results['size']/1024/1024:.2f} MB)")
    
    # Firmware Volumes
    print("\n" + "=" * 80)
    print("一、固件卷 (Firmware Volumes) 列表")
    print("=" * 80)
    print(f"\n共发现 {len(results['firmware_volumes'])} 个固件卷:")
    print("-" * 80)
    print(f"{'序号':<6}{'GUID':<40}{'偏移地址':<16}{'大小':<16}")
    print("-" * 80)
    
    for i, fv in enumerate(results['firmware_volumes'], 1):
        guid = fv.get('guid', 'N/A')
        offset = fv.get('offset', 0)
        size = fv.get('size', 0)
        print(f"{i:<6}{guid:<40}0x{offset:08X}      {size/1024:.1f} KB")
    
    # Setup Modules
    print("\n" + "=" * 80)
    print("二、Setup 相关模块列表")
    print("=" * 80)
    
    # Group by GUID
    setup_by_guid = {}
    for mod in results['setup_modules']:
        guid = mod.get('guid', 'N/A')
        if guid not in setup_by_guid:
            setup_by_guid[guid] = []
        setup_by_guid[guid].append(mod)
    
    print(f"\n共发现 {len(results['setup_modules'])} 个 Setup 相关模块，涉及 {len(setup_by_guid)} 个唯一 GUID:")
    print("-" * 80)
    
    # Key modules first
    key_guids = [
        ('899407D7-99FE-43D8-9A21-79EC328CAC21', 'AMITSE/Setup'),
        ('B1DA0ADF-4F77-4070-A88E-BFFE1C60529A', 'AMITSESetupData'),
        ('EE4E5898-3914-4259-9D6E-DC7BD79403CF', 'AMITSE/AMITSESetupData'),
        ('A59A0056-3341-44B5-9F89-379D6D011A73', 'SetupUtility'),
    ]
    
    print("\n【核心 Setup 模块】")
    for guid, desc in key_guids:
        if guid in setup_by_guid:
            mods = setup_by_guid[guid]
            print(f"\n  GUID: {guid}")
            print(f"  描述: {desc}")
            print(f"  模块数量: {len(mods)}")
            for mod in mods:
                name = mod.get('name', 'N/A') or '(未命名)'
                offset = mod.get('offset', 0)
                size = mod.get('size', 0)
                print(f"    - {name}")
                print(f"      类型: {mod.get('type', 'N/A')}")
                print(f"      偏移: 0x{offset:08X}, 大小: {size:,} bytes ({size/1024:.1f} KB)")
    
    print("\n【其他 Setup 相关模块】")
    other_count = 0
    for guid, mods in setup_by_guid.items():
        if guid not in [g for g, _ in key_guids]:
            if other_count < 20:  # Show first 20
                for mod in mods:
                    name = mod.get('name', 'N/A') or '(未命名)'
                    if name != '(未命名)':
                        print(f"\n  模块: {name}")
                        print(f"  GUID: {guid}")
                        print(f"  偏移: 0x{mod.get('offset', 0):08X}, 大小: {mod.get('size', 0)} bytes")
                        break
            other_count += 1
    
    if other_count > 20:
        print(f"\n  ... 还有 {other_count - 20} 个其他模块 ...")
    
    # NVRAM Regions
    print("\n" + "=" * 80)
    print("三、NVRAM 变量存储区域")
    print("=" * 80)
    print(f"\n共发现 {len(results['nvram_regions'])} 个 NVRAM 相关区域:")
    print("-" * 80)
    print(f"{'名称':<40}{'GUID':<40}{'大小':<12}")
    print("-" * 80)
    
    seen_nvram = set()
    for nv in results['nvram_regions']:
        name = nv.get('name', 'N/A')
        guid = nv.get('guid', 'N/A')
        size = nv.get('size', 0)
        key = f"{name}_{guid}"
        if key not in seen_nvram:
            seen_nvram.add(key)
            print(f"{name:<40}{guid:<40}{size:<12}")
    
    # Extracted Files
    print("\n" + "=" * 80)
    print("四、提取的文件")
    print("=" * 80)
    
    if os.path.exists(EXTRACTED_DIR):
        files = os.listdir(EXTRACTED_DIR)
        print(f"\n共提取 {len(files)} 个文件到 {EXTRACTED_DIR}:")
        print("-" * 80)
        print(f"{'文件名':<50}{'大小':<16}")
        print("-" * 80)
        
        for f in sorted(files):
            fpath = os.path.join(EXTRACTED_DIR, f)
            size = get_file_size(fpath)
            print(f"{f:<50}{size:>10,} bytes")
    
    # IFR Analysis
    print("\n" + "=" * 80)
    print("五、IFR (Internal Form Representation) 数据分析")
    print("=" * 80)
    print("\nIFR 数据是 BIOS 设置菜单的内部表示形式，包含表单、选项和配置信息。")
    print("\n在提取的模块中发现的 IFR 相关位置:")
    print("-" * 80)
    
    # Check extraction log for IFR locations
    extraction_log = "/workspace/bios_analysis/extraction_log.txt"
    if os.path.exists(extraction_log):
        with open(extraction_log, 'r') as f:
            content = f.read()
            # Find IFR section
            if "IFR locations found" in content:
                print("\n  IFR 发现位置 (基于原始二进制扫描):")
                # Extract IFR lines
                lines = content.split('\n')
                in_ifr = False
                count = 0
                for line in lines:
                    if "IFR locations found" in line:
                        in_ifr = True
                        continue
                    if in_ifr and line.strip().startswith('-'):
                        if count < 20:
                            print(f"    {line.strip()}")
                        count += 1
                    elif in_ifr and line.strip() and not line.startswith(' '):
                        break
                if count > 20:
                    print(f"    ... 还有 {count - 20} 个位置 ...")
    
    # Summary
    print("\n" + "=" * 80)
    print("六、分析总结")
    print("=" * 80)
    print(f"""
1. 固件类型: AMI Aptio UEFI BIOS (32MB)
2. 固件卷数量: {len(results['firmware_volumes'])}
3. 扫描模块总数: {results['all_modules_count']}
4. Setup 相关模块: {len(results['setup_modules'])}
5. NVRAM 相关区域: {len(results['nvram_regions'])}
6. IFR/Form 相关模块: {len(results.get('ifr_sections', []))}

关键 Setup 模块 GUID:
  - AMITSE/Setup:         899407D7-99FE-43D8-9A21-79EC328CAC21
  - AMITSESetupData:      B1DA0ADF-4F77-4070-A88E-BFFE1C60529A
  - AMITSE:               EE4E5898-3914-4259-9D6E-DC7BD79403CF

提取文件保存位置:
  - 原始模块: /workspace/bios_analysis/extracted/
  - 分析结果: /workspace/bios_analysis/analysis_results.json
  - 分析日志: /workspace/bios_analysis/analysis_log.txt
  - 提取日志: /workspace/bios_analysis/extraction_log.txt
""")
    
    print("=" * 80)
    print("分析完成")
    print("=" * 80)

if __name__ == '__main__':
    generate_report()
