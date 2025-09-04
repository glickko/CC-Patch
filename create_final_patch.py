

from pathlib import Path

# --- Confirmed Patch Configurations ---
PATCHES = [
    {
        "name": "Anti-Debug TLS Callback Patch",
        "offset": 0x19B50,
        "original": b'\x48\x89\x5C\x24\x08', # A standard function start
        "modified": b'\xC3\x90\x90\x90\x90'  # RET + NOP padding
    },
    {
        "name": "Secondary IsDebuggerPresent Check Patch",
        "offset": 0x21DC8,
        "original": b'\x74\x1D', # JE (Jump if Equal) instruction
        "modified": b'\xEB\x1D'  # JMP (Jump) instruction
    }
]

def create_final_patched_file():
    """Applies multiple patches to the DLL."""
    print("--- Final Multi-Patcher for VESafeGuard.dll ---")

    try:
        original_path_str = input("\n[1] Drag the ORIGINAL VESafeGuard.dll here and press Enter: ")
        original_path = Path(original_path_str.strip().replace('"', ''))
        if not original_path.is_file() or original_path.name.lower() != 'vesafeguard.dll':
            print("\n[ERROR] This is not a valid VESafeGuard.dll file.")
            return
    except Exception:
        print("\n[ERROR] Invalid file path.")
        return

    output_path = original_path.parent / "VESafeGuard.dll.patched"
    print(f"\n[INFO] The patched file will be saved as: {output_path}")

    print("[INFO] Reading original file...")
    data = bytearray(original_path.read_bytes())
    
    all_patches_verified = True
    for patch in PATCHES:
        print(f"[INFO] Verifying '{patch['name']}' at offset {hex(patch['offset'])}...")
        offset = patch['offset']
        original = patch['original']
        if data[offset:offset+len(original)] != original:
            print(f"\n[FATAL ERROR] for patch '{patch['name']}'.")
            print(f"The bytes at the target offset are not what we expected.")
            print("This script is for a different file version.")
            all_patches_verified = False
            break

    if not all_patches_verified:
        return

    print("\n[SUCCESS] All patch locations verified. Applying changes...")
    for patch in PATCHES:
        offset = patch['offset']
        modified = patch['modified']
        data[offset:offset+len(modified)] = modified
    
    output_path.write_bytes(data)
    
    print("\n-------------------------------------------")
    print(">>> FINAL PATCHING COMPLETE <<<")
    print("-------------------------------------------")
    print(f"\nYour new file 'VESafeGuard.dll.patched' has been created.")
    print("This file should have anti-debugging and the primary checks disabled.")

if __name__ == "__main__":
    create_final_patched_file()
    input("\nPress Enter to exit.")

