# Challenge 4 — "The Loyal Printer"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"They say a confession unspoken is still a confession.*
> *He sent three jobs to the printer.*
> *The printer never forgot.*
> *Can you read what was never meant to be read?"*
>
> Gotham PD forensic imaging recovered the Windows print spooler
> directory from Edward Nashton's machine. Three jobs were queued.
> None ever printed.
>
> The spooler remembers everything.

**Files:** `00001.SHD`, `00001.SPL`, `00002.SHD`, `00002.SPL`, `00003.SHD`, `00003.SPL`
**Category:** Forensics
**Difficulty:** Hard
**Points:** 500

---

## 🎯 Intended Solve Path

### Step 1 — Understand the file types
Windows print spooler creates two files per job:
- `.SHD` — Shadow file: binary header with job metadata (user, machine, printer, document title)
- `.SPL` — Spool file: the actual print data (EMF, RAW, PCL, etc.)

Both live in `C:\Windows\System32\spool\PRINTERS\`

### Step 2 — Parse each .SHD file

The SHD format (Windows XP/Vista+):
```
Offset  Size  Field
0x00    4     Magic / Version (0x00000400 = valid Windows XP+)
0x04    4     Total size
0x08    4     Reserved
0x0C    4     JobId
0x10    4     Priority
0x14    4     Status flags
0x18    4     Submitted timestamp
0x1C    4     StartTime
0x20    4     UntilTime
0x24    4     Size (SPL file size)
0x28    4     cbSecurityDescriptor
0x2C    4     offSecurityDescriptor
0x30    ...   WORD-prefixed UTF-16LE strings:
              UserName, MachineName, PrinterName, DocName,
              DataType, PrintProcessor, Parameters, DriverName
```

Parse with Python:
```python
import struct

def read_wstr(data, offset):
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if length == 0: return "", offset
    s = data[offset:offset+length].decode('utf-16-le', errors='replace')
    return s, offset + length

def parse_shd(path):
    data = open(path, 'rb').read()
    magic = struct.unpack_from('<I', data, 0)[0]
    print(f"Magic: 0x{magic:08X}")
    if magic != 0x00000400:
        print("INVALID MAGIC — corrupt job")
        return
    offset = 48
    for field in ["UserName","MachineName","PrinterName","DocName",
                  "DataType","PrintProcessor","Parameters","DriverName"]:
        val, offset = read_wstr(data, offset)
        print(f"  {field}: {val!r}")
```

### Step 3 — Triage all three jobs

| Job | SHD Magic | Status | SPL | Verdict |
|-----|-----------|--------|-----|---------|
| 00001 | `0x00000400` ✅ | 0x00 (queued) | Valid EMF stream | **VALID** |
| 00002 | `0x00000400` ✅ | 0x10 (error) | Truncated, corrupt tail | Corrupt SPL |
| 00003 | `0xDEADBEEF` ❌ | 0x00 | Empty | Invalid job entirely |

### Step 4 — Read the red herrings

**00002.SPL** — Contains a readable string:
```
securinets_isgt{c0rrupt_spl_d3c0y}
```
This is a trap. The SPL is truncated and the job has error status. The flag inside is fake.

**00003.SHD** — DocName field (if players try to parse despite bad magic):
```
securinets_isgt{wr0ng_j0b_wr0ng_ans}
```
Also fake. Job has invalid magic — the entire record is corrupt and untrustworthy.

**00001.SPL** — EMF stream contains:
```
securinets_isgt{f4k3_spl_str1ng}
```
Also fake. The flag is NOT in the SPL content.

### Step 5 — Extract flag from 00001.SHD metadata

The only valid, non-corrupt job is `00001`. Its metadata fields:

```
UserName    : 'sp1ll'
MachineName : 's3cr3ts'
PrinterName : 'GCPD-EVIDENCE-PRN-04'
DocName     : 'pr1nt_j0bs'
```

The three unusual values spell out the flag:
```
securinets_isgt{ DocName _ UserName _ MachineName }
             = { pr1nt_j0bs _ sp1ll _ s3cr3ts }
```

**Flag:** `securinets_isgt{pr1nt_j0bs_sp1ll_s3cr3ts}`

---

## 🚩 Flag
```
securinets_isgt{pr1nt_j0bs_sp1ll_s3cr3ts}
```

---

## 🔴 Red Herrings Explained

| Location | Content | Why it's a trap |
|---|---|---|
| `00002.SPL` bytes | `securinets_isgt{c0rrupt_spl_d3c0y}` | SPL is truncated, job has error status — unreliable source |
| `00003.SHD` DocName | `securinets_isgt{wr0ng_j0b_wr0ng_ans}` | Magic is `0xDEADBEEF` — invalid job, metadata untrustworthy |
| `00001.SPL` EMF stream | `securinets_isgt{f4k3_spl_str1ng}` | Flag is in SHD metadata, not SPL content |
| `00002.SHD` DocName | `Gotham_Renewal_Dossier_FINAL.pdf` | Looks like a real document, distracts from job 1 |

---

## 🛠️ Tools Players Might Use
- Python `struct` module (manual parsing — intended path)
- `parse_shd.py` (if they write their own parser)
- **010 Editor** with SHD template
- **WinPrefetchView** / **SpoolView** (Windows tools)
- `strings` on SHD files (won't work — UTF-16LE, not ASCII)
- `strings -e l` (little-endian 16-bit — will expose UTF-16LE strings)

**Key insight:** `strings` on a UTF-16LE file shows garbage unless you use `-e l` flag.
Players who use `strings 00001.SHD` will see noise and think it's encrypted.
Players who use `strings -e l 00001.SHD` will see the flag parts immediately.

---

## 💡 Hint (optional, costs points)
> *"The document never printed.*
> *But the job remembers who sent it,*
> *from which machine, under which name.*
> *Three fields. Three pieces.*
> *The format is wide — not narrow."*
> — UTF-16LE, not ASCII. And look at the metadata, not the content.

---

## 📚 What This Teaches
- Windows print spooler forensics (real investigative technique)
- Binary format parsing with `struct`
- SHD vs SPL distinction — metadata vs content
- UTF-16LE string encoding
- Triaging corrupt vs valid artifacts before analysis
- Not trusting content found in corrupt/invalid records
