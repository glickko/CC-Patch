

from pathlib import Path

def format_hex(byte_string):
    """Formats a byte string into a readable hex string like '0F 84 59'."""
    return ' '.join(f'{b:02X}' for b in byte_string)

def compare_files(original_file: Path, modified_file: Path, output_file: Path):
    """Compares two files and writes the differences to an output file."""
    if not original_file.exists():
        print(f"Error: Original file not found at {original_file}")
        return
    if not modified_file.exists():
        print(f"Error: Modified file not found at {modified_file}")
        return

    print("Reading files...")
    original_data = original_file.read_bytes()
    modified_data = modified_file.read_bytes()

    min_len = min(len(original_data), len(modified_data))
    diffs = []
    i = 0
    
    print("Finding differences...")
    while i < min_len:
        if original_data[i] != modified_data[i]:
            # A difference is found, now find how long it is
            start_offset = i
            
            # Find where the differing block ends
            while i < min_len and original_data[i] != modified_data[i]:
                i += 1
            end_offset = i
            
            diffs.append({
                'offset': start_offset,
                'original': original_data[start_offset:end_offset],
                'modified': modified_data[start_offset:end_offset],
            })
        else:
            i += 1
            
    print(f"Found {len(diffs)} differing block(s).")

    # Write the results to the output file
    with open(output_file, 'w') as f:
        f.write("--- Hex Patch Data ---\n")
        f.write("Please provide this entire file to your assistant.\n\n")
        
        for i, diff in enumerate(diffs, 1):
            f.write(f"--- Patch {i} ---\n")
            f.write(f"Offset:   {hex(diff['offset'])}\n")
            f.write(f"Original: {format_hex(diff['original'])}\n")
            f.write(f"Modified: {format_hex(diff['modified'])}\n\n")
            
    print(f"Successfully wrote differences to '{output_file.name}'")


def main():
    """Main function to set up paths and start the comparison."""
    base_dir = Path(__file__).resolve().parent
    original_dll = base_dir / "Patch" / "original" / "VECreator.dll"
    patched_dll = base_dir / "Patch" / "patched" / "VECreator.dll"
    output_txt = base_dir / "hex_differences.txt"
    
    compare_files(original_dll, patched_dll, output_txt)

if __name__ == "__main__":
    main()

