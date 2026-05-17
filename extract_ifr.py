import sys
import os
import struct
import json

sys.path.insert(0, '/root/.pyenv/versions/3.14.4/lib/python3.14/site-packages')

try:
    import uefi_firmware
    print("uefi_firmware imported successfully")
except Exception as e:
    print(f"Failed to import uefi_firmware: {e}")
    sys.exit(1)

rom_path = "/workspace/extracted/code$GetExtractPath$/IMAGEM2C.rom"
print(f"Parsing ROM: {rom_path}")

with open(rom_path, 'rb') as f:
    data = f.read()

print(f"ROM size: {len(data)} bytes")

# Parse firmware
parser = uefi_firmware.AutoParser(data)
firmware = parser.parse()

if firmware is None:
    print("Failed to parse firmware")
    sys.exit(1)

print(f"Firmware type: {type(firmware)}")

# Walk firmware objects to find Setup-related modules
def walk_objects(obj, depth=0):
    indent = "  " * depth
    obj_type = type(obj).__name__
    
    # Check for objects with data
    if hasattr(obj, 'data') and obj.data:
        # Look for Setup-related GUIDs or names
        name = getattr(obj, 'name', '') or ''
        guid = getattr(obj, 'guid', '') or ''
        
        if not isinstance(name, str):
            name = str(name)
        if not isinstance(guid, str):
            guid = str(guid)
        
        # Search for setup-related strings in data
        data_str = ''
        try:
            data_str = obj.data.decode('utf-16-le', errors='ignore')
        except:
            try:
                data_str = obj.data.decode('ascii', errors='ignore')
            except:
                pass
        
        is_setup = False
        setup_keywords = ['Setup', 'setup', 'SETUP', 'IFR', 'HII', 'PlatformSetup']
        for kw in setup_keywords:
            if kw in name or kw in guid or kw in data_str[:1000]:
                is_setup = True
                break
        
        if is_setup or 'setup' in obj_type.lower():
            print(f"{indent}[{obj_type}] name={name} guid={guid} size={len(obj.data)}")
            # Save for analysis
            if len(obj.data) > 100:
                safe_name = name.replace('/', '_').replace('\\', '_').replace(':', '_') or f"obj_{depth}"
                out_path = f"/workspace/setup_{safe_name}_{len(obj.data)}.bin"
                with open(out_path, 'wb') as outf:
                    outf.write(obj.data)
                print(f"{indent}  Saved to {out_path}")
    
    # Recurse into children
    if hasattr(obj, 'objects'):
        for child in obj.objects:
            walk_objects(child, depth + 1)

walk_objects(firmware)
print("Done walking firmware")
