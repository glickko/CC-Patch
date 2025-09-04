# =============================================================================
# Signature Scanner for CapCut v6.6 (v2 - with Diagnostics & File Output)
# Author: Gemini
# Date: July 13, 2025
#
# This script analyzes a DLL for potential patch locations by finding
# keywords and looking for nearby conditional jump instructions.
# It now includes real-time progress updates and saves results to a file.
# =============================================================================

from pathlib import Path
import re
import time

def scan_for_signatures():
    """Scans the DLL for potential patch targets with progress and file output."""
    print("--- Automated Signature Scanner v2 ---")

    try:
        dll_path_str = input("\n[1] Drag the ORIGINAL VECreator.dll (v6.6) here and press Enter: ")
        dll_path = Path(dll_path_str.strip().replace('"', ''))
        if not dll_path.is_file():
            print("\n[ERROR] Invalid file path.")
            return
    except Exception:
        print("\n[ERROR] Could not read file path.")
        return

    output_filename = "scan_results.txt"
    print(f"\n[INFO] Reading '{dll_path.name}'...")
    try:
        data = dll_path.read_bytes()
    except Exception as e:
        print(f"\n[ERROR] Could not read file: {e}")
        return

    keywords = [b'VIP', b'Pro', b'premium', b'login', b'purchase', b'export']
    vulnerable_opcodes = [b'\x74', b'\x75'] # JE, JNE (short jumps)
    
    print(f"[INFO] Starting scan on {len(data) / 1024 / 1024:.2f} MB of data...")
    start_time = time.time()
    potential_locations = []

    # --- REAL-TIME DIAGNOSTIC ---
    for i, keyword in enumerate(keywords):
        print(f"[SCANNING {i+1}/{len(keywords)}] Searching for keyword: '{keyword.decode()}'...")
        
        for match in re.finditer(re.escape(keyword), data, re.IGNORECASE):
            keyword_offset = match.start()
            scan_start = max(0, keyword_offset - 200)
            scan_window = data[scan_start:keyword_offset]
            
            for opcode in vulnerable_opcodes:
                for opcode_match in re.finditer(re.escape(opcode), scan_window):
                    patch_candidate_offset = scan_start + opcode_match.start()
                    if patch_candidate_offset not in [loc['offset'] for loc in potential_locations]:
                        potential_locations.append({
                            'offset': patch_candidate_offset,
                            'keyword': keyword.decode(),
                            'opcode': opcode.hex().upper()
                        })

    end_time = time.time()
    print(f"\n[INFO] Scan finished in {end_time - start_time:.2f} seconds.")

    if not potential_locations:
        print("\n[RESULT] No obvious patch locations were found.")
        return

    # --- OUTPUT TO TXT FILE ---
    print(f"[INFO] Saving results to '{output_filename}'...")
    potential_locations.sort(key=lambda x: x['offset'])
    
    with open(output_filename, 'w') as f:
        f.write("--- Automated Signature Scan Results ---\n")
        f.write(f"Target File: {dll_path.name}\n")
        f.write(f"Timestamp: {time.ctime()}\n")
        f.write("------------------------------------------\n\n")
        f.write("Found the following potential patch locations:\n\n")
        for loc in potential_locations:
            f.write(f"  - Offset: {hex(loc['offset'])}\n")
            f.write(f"    Opcode: {loc['opcode']} (JE/JNE)\n")
            f.write(f"    Found Near Keyword: '{loc['keyword']}'\n\n")

    print("\n-------------------------------------------")
    print(">>> ANALYSIS COMPLETE <<<")
    print("-------------------------------------------")
    print(f"Results have been saved to {output_filename}")
    print("Please review the file and provide me with the most promising offset.")


if __name__ == "__main__":
    scan_for_signatures()
    input("\nPress Enter to exit.")
