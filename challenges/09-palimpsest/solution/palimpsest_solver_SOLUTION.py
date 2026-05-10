#!/usr/bin/env python3
"""
Palimpsest — PDF layer solver (solution tool)
Peels back incremental updates to recover the original document content.

Usage: python3 palimpsest_solver_SOLUTION.py confession_redacted.pdf
"""
import re, zlib, sys

def solve(path):
    raw = open(path, 'rb').read()

    print("=" * 60)
    print("PALIMPSEST — PDF Layer Analysis")
    print("=" * 60)

    # Step 1: count EOF markers
    eofs = [m.start() for m in re.finditer(rb'%%EOF', raw)]
    print(f"\n[1] %%EOF markers found: {len(eofs)}")
    for i, pos in enumerate(eofs):
        print(f"    Layer {i} ends at offset {pos}")

    # Step 2: extract startxref values (oldest first)
    sxrefs = [int(x) for x in re.findall(rb'startxref\n(\d+)', raw)]
    print(f"\n[2] startxref chain: {sxrefs}")
    print(f"    Oldest (original) xref at offset: {sxrefs[0]}")

    # Step 3: extract all versions of obj 3 (Info/metadata)
    print(f"\n[3] All versions of object 3 (Info/metadata):")
    objs3 = re.findall(rb'3 0 obj.*?endobj', raw, re.DOTALL)
    for i, o in enumerate(objs3):
        author = re.search(rb'/Author \((.+?)\)', o)
        mod    = re.search(rb'/ModDate \((.+?)\)', o)
        a_str  = author.group(1).decode('latin-1') if author else 'N/A'
        m_str  = mod.group(1).decode('latin-1') if mod else 'N/A'
        marker = " ← ORIGINAL" if i == 0 else ""
        print(f"    Version {i+1}: Author={a_str!r:30s}  ModDate={m_str}{marker}")

    flag_part1 = objs3[0]
    m = re.search(rb'/Author \((.+?)\)', flag_part1)
    part1 = m.group(1).decode() if m else "???"
    print(f"\n    FLAG PART 1 (original Author): {part1!r}")

    # Step 4: extract and decompress all content streams
    print(f"\n[4] Content streams (decompressed):")
    streams = []
    for i, m in enumerate(re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.DOTALL)):
        try:
            dec = zlib.decompress(m.group(1)).decode('latin-1')
            streams.append(dec)
            label = " ← ORIGINAL" if i == 0 else ""
            # Extract authorization code if present
            auth = re.search(r'Authorization code: ([0-9a-f]+)', dec)
            if auth:
                hex_val = auth.group(1)
                decoded = bytes.fromhex(hex_val).decode()
                print(f"    Stream {i+1}: Authorization code: {hex_val}{label}")
                print(f"             Hex decoded → {decoded!r}")
            else:
                # Show first line of content
                first_line = dec.split('\n')[3:4]
                print(f"    Stream {i+1}: {first_line}{label}")
        except Exception as e:
            print(f"    Stream {i+1}: decompress failed ({e})")

    # Find hex-encoded part 2 in stream 1
    part2 = "???"
    if streams:
        auth = re.search(r'Authorization code: ([0-9a-f]+)', streams[0])
        if auth:
            part2 = bytes.fromhex(auth.group(1)).decode()

    print(f"\n    FLAG PART 2 (hex in original stream): {part2!r}")

    # Step 5: reconstruct
    print(f"\n[5] Flag reconstruction:")
    print(f"    Part 1: {part1}")
    print(f"    Part 2: {part2}")
    flag = f"securinets_isgt{{{part1}_{part2}}}"
    print(f"\n{'=' * 60}")
    print(f"FLAG: {flag}")
    print(f"{'=' * 60}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 palimpsest_solver_SOLUTION.py <pdf_file>")
        sys.exit(1)
    solve(sys.argv[1])
