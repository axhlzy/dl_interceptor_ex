#!/usr/bin/env python3
"""Convert a binary file to a C header with a hex array."""
import sys
import os

def bin2hex(input_path, var_name):
    with open(input_path, "rb") as f:
        data = f.read()

    out = f"// Auto-generated from {os.path.basename(input_path)}\n"
    out += f"// Size: {len(data)} bytes\n"
    out += f"#pragma once\n\n"
    out += f"static const unsigned char {var_name}[] = {{\n"

    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = ", ".join(f"0x{b:02x}" for b in chunk)
        out += f"    {hex_str},\n"

    out += f"}};\n"
    out += f"static const unsigned int {var_name}_len = {len(data)};\n"
    return out

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <input_file> <var_name> <output_header>")
        sys.exit(1)

    header = bin2hex(sys.argv[1], sys.argv[2])
    with open(sys.argv[3], "w") as f:
        f.write(header)
    print(f"Generated {sys.argv[3]} ({os.path.getsize(sys.argv[1])} bytes)")
