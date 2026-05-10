# Challenge 10 — "Palimpsest"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"A palimpsest: a manuscript where the old writing*
> *shows through the new.*
> *They thought they could erase me.*
> *They thought sanitizing the document*
> *would sanitize the truth.*
> *Read what was written first.*
> *Then read it again.*
> *The confession was always there."*
>
> Gotham PD recovered this PDF from the Mayor's office servers.
> It appears blank — just a Renewal Initiative placeholder.
> Three rounds of "sanitization" were applied before it was filed.
> None of them actually erased anything.
>
> Peel back the layers.

**File:** `confession_redacted.pdf`
**Category:** Forensics — Document
**Difficulty:** Hard
**Points:** 600

---

## 🎯 Intended Solve Path

### Step 1 — Open the PDF

A PDF viewer shows: `"GOTHAM CITY - OFFICE OF THE MAYOR / RENEWAL INITIATIVE / This document is intentionally blank."`

No flag visible. Looks sanitized.

### Step 2 — Identify the structure

```bash
strings confession_redacted.pdf | grep -E "%%EOF|startxref|obj"
```

Or inspect raw bytes:
```bash
grep -c "%%EOF" confession_redacted.pdf
# → 4
```

**4 `%%EOF` markers = 1 original body + 3 incremental updates.**

PDF incremental updates append new content after `%%EOF` without modifying what came before. The original data is still physically present in the file.

### Step 3 — Find all startxref values

```bash
grep -a "startxref" confession_redacted.pdf
```

Output:
```
startxref
1084
%%EOF
...
startxref
1806
%%EOF
...
startxref
2501
%%EOF
...
startxref
3112
%%EOF
```

The **oldest** (smallest) `startxref` value points to the original xref table: offset `1084`.

### Step 4 — Parse the original xref table

Jump to offset 1084 in the file:
```bash
python3 -c "
data = open('confession_redacted.pdf','rb').read()
print(data[1084:1200].decode('latin-1'))
"
```

The original xref maps object numbers to byte offsets. Note the offsets for:
- **Object 3** (Info/metadata dictionary) 
- **Object 5** (content stream)

### Step 5 — Extract all versions of object 3 (metadata)

```python
import re

raw = open('confession_redacted.pdf', 'rb').read()
objs = re.findall(rb'3 0 obj.*?endobj', raw, re.DOTALL)
for i, o in enumerate(objs):
    author = re.search(rb'/Author \((.+?)\)', o)
    print(f"Version {i+1}: Author = {author.group(1).decode() if author else 'N/A'}")
```

Output:
```
Version 1: Author = pdf_l4y3rs          ← ORIGINAL — FLAG PART 1
Version 2: Author = E. Nashton - REDACTED
Version 3: Author = Office of the Mayor
Version 4: Author = GCPD Records Office
```

**Flag Part 1: `pdf_l4y3rs`**

### Step 6 — Extract and decompress all content streams

```python
import zlib, re

raw  = open('confession_redacted.pdf', 'rb').read()
for i, m in enumerate(re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.DOTALL)):
    try:
        dec = zlib.decompress(m.group(1)).decode()
        print(f"\n--- Stream {i+1} ---")
        print(dec[:300])
    except:
        pass
```

Stream 1 (original) contains:
```
...
(Authorization code: 6e337633725f7472756c795f3372347333) Tj
...
```

The authorization code is a hex string. Decode it:
```python
bytes.fromhex("6e337633725f7472756c795f3372347333").decode()
# → n3v3r_truly_3r4s3
```

**Flag Part 2: `n3v3r_truly_3r4s3`**

### Step 7 — Reconstruct the flag

```
Part 1 (from original Author field):     pdf_l4y3rs
Part 2 (from original stream, hex):      n3v3r_truly_3r4s3
```

```
securinets_isgt{ pdf_l4y3rs _ n3v3r_truly_3r4s3 }
```

**Flag:** `securinets_isgt{pdf_l4y3rs_n3v3r_truly_3r4s3}`

---

## 🚩 Flag
```
securinets_isgt{pdf_l4y3rs_n3v3r_truly_3r4s3}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| Visible PDF content | "Intentionally blank" | Update 3 — the final sanitization layer |
| Update 2 Author: "Office of the Mayor" | Sounds official/final | Just the second overwrite — not original |
| Update 1 Author: "E. Nashton - REDACTED" | Nashton's name visible → must be the answer | Wrong version — not the original |
| Hex string in stream | Random authorization code | Encodes flag part 2 — requires hex decode |
| 3 updates visible | Only need to go back 1 layer | Must go back to the very first version (layer 0) |

---

## 🛠️ Tools Players Might Use

```bash
# Count incremental updates
strings confession_redacted.pdf | grep -c "%%EOF"

# Extract all startxref values  
grep -a "startxref" confession_redacted.pdf

# pdf-parser (Didier Stevens)
pdf-parser.py confession_redacted.py -s "obj 3"
pdf-parser.py confession_redacted.py -o 5 -f -d stream.bin

# peepdf
peepdf confession_redacted.pdf
  > versions
  > stream 5 0   (in version 0 = original)

# qpdf — list all versions
qpdf --show-xref confession_redacted.pdf

# Python manual approach (most educational)
python3 palimpsest_solver_SOLUTION.py confession_redacted.pdf
```

**Key insight:** PDF incremental updates never erase — they only append. Every "sanitized" version still contains all previous versions verbatim. The `startxref` chain links them together oldest-to-newest.

---

## 💡 Hint (optional, costs points)
> *"Every version of this document is still here.*
> *Count the endings. Find the first one.*
> *Then look at what the author called themselves*
> *before they had reason to hide."*
> — Count `%%EOF`. The smallest `startxref` is the oldest. Check the Author field.

---

## 📚 What This Teaches
- PDF incremental update structure
- How "sanitized" PDFs leak original content
- xref table chain navigation (Prev pointer)
- FlateDecode stream decompression
- Metadata forensics (Info dictionary)
- Why PDF redaction requires specialized tools — not just overwriting
- Real-world relevance: this is how classified document leaks happen
