#!/usr/bin/env python3
"""Convert a binary file to a C header with a hex array."""
import sys
import os

def bin2hex(input_path, var_name, output_path):
    with open(input_path, "rb") as f_in:
        data = f_in.read()

    total_len = len(data)
    with open(output_path, "w") as f_out:
        f_out.write(f"// Auto-generated from {os.path.basename(input_path)}\n")
        f_out.write(f"// Size: {total_len} bytes\n")
        f_out.write(f"#pragma once\n\n")
        f_out.write(f"static const unsigned char {var_name}[] = {{\n")

        for i in range(0, total_len, 16):
            chunk = data[i:i+16]
            hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
            f_out.write(f"    {hex_str},\n")
            
            # Print progress for large files (e.g. over 1MB)
            if total_len > 1024 * 1024 and i > 0 and i % (1048576 * 5) == 0:
                print(f"  ... encoded {i // 1048576} MB / {total_len // 1048576} MB ...", flush=True)

        f_out.write(f"}};\n")
        f_out.write(f"static const unsigned int {var_name}_len = {total_len};\n")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input_file> <var_name> <output_header>")
        sys.exit(1)

    input_file = sys.argv[1]
    var_name = sys.argv[2]
    output_file = sys.argv[3]
    
    bin2hex(input_file, var_name, output_file)
    print(f"Generated {output_file} ({os.path.getsize(input_file)} bytes)")
