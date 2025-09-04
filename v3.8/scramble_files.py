

import os
from pathlib import Path


SECRET_KEY = b"your-super-secret-key-glickko-123"

def process_file(source_path: Path, dest_path: Path, key: bytes):
    """Reads a file, XORs its content with the key, and writes the result."""
    print(f"Processing: {source_path.name}...")
    
    # Ensure the destination directory exists
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    
    try:
        with open(source_path, 'rb') as f_in, open(dest_path, 'wb') as f_out:
            i = 0
            while True:
                byte = f_in.read(1)
                if not byte:
                    break
                # XOR the byte with a byte from the key
                scrambled_byte = bytes([byte[0] ^ key[i % len(key)]])
                f_out.write(scrambled_byte)
                i += 1
    except Exception as e:
        print(f"  [ERROR] Could not process {source_path.name}: {e}")

def main():
    """Main function to find and process all patch files."""
    base_dir = Path(__file__).resolve().parent
    source_dir = base_dir / "Patch"
    dest_dir = base_dir / "ScrambledPatch"

    if not source_dir.exists():
        print(f"[ERROR] The 'Patch' folder was not found in this directory.")
        print("Please make sure it exists before running this script.")
        return

    print("--- Starting File Scrambler ---")
    
    files_to_scramble = [
        source_dir / "original" / "VECreator.dll",
        source_dir / "patched" / "VECreator.dll",
        source_dir / "patched" / "DLLLoader64_6E8D.exe",
        source_dir / "patched" / "DLLLoader64_D057.exe",
    ]

    for file_path in files_to_scramble:
        if file_path.exists():
            # Maintain the same subfolder structure (original/ or patched/)
            relative_path = file_path.relative_to(source_dir)
            destination_path = dest_dir / relative_path
            process_file(file_path, destination_path, SECRET_KEY)
        else:
            print(f"  [WARNING] File not found, skipping: {file_path}")

    print("\n--- Scrambling Complete! ---")
    print(f"Your scrambled files are now in the '{dest_dir.name}' folder.")
    print("You can now use this folder to build the secure version of your launcher.")

if __name__ == "__main__":
    main()

