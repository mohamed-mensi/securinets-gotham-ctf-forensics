# 🦇 Securinets ISGT — Forensics CTF Solutions
## Theme: The Riddler / *The Batman* (2022)
### Flag format: `securinets_isgt{...}`

---

# Challenge 1 — "The Screenshot That Shouldn't Exist"
**Points:** 200 (dynamic) | **Difficulty:** Easy

## Description
> *"I left you a picture. Not of what I did — of the moment before. The clock doesn't lie. The taskbar remembers. What was I reading when this was taken?"*
>
> Gotham PD recovered a screenshot from Nashton's workstation and a Windows event log from the same machine. The screenshot shows a frozen moment — open apps, a timestamp, a partial filename in the taskbar. The event log shows what was accessed and when.

**Files:** `screenshot.png`, `events.evtx`

## Solve Path

### Step 1 — Read the screenshot
Note the exact time visible on the system clock. Note any partial filenames visible in the taskbar or open windows.

### Step 2 — Parse the EVTX file
```bash
# Using python-evtx
python3 -c "
import Evtx.Evtx as evtx
import Evtx.Views as e_views
with evtx.Evtx('events.evtx') as log:
    for record in log.records():
        print(record.xml())
" | grep -i "ObjectName\|ProcessName\|TimeCreated"
```
Or use **Event Log Explorer** / **FullEventLogView** on Windows.

### Step 3 — Correlate timestamp
Find the event log entry matching the timestamp from the screenshot minus 1 minute. The `ObjectName` field of a file access event (Event ID 4663) reveals the full path of the last accessed file.

### Step 4 — Extract the flag
The flag is embedded in the content or filename of the identified file.

## Flag
```
securinets_isgt{...}
```
*(flag depends on your specific implementation)*

## What This Teaches
- Windows Event Log (EVTX) forensics
- File access event correlation (Event ID 4663)
- Timestamp-based artifact correlation
- Visual + log cross-referencing

---

# Challenge 2 — "The Empty Email"
**Points:** 300 (dynamic, min 75) | **Difficulty:** Medium

## Description
> *"I sent him a message. He never read it. Or did he? Maybe he read everything and understood nothing. Can you do better, detective?"*
>
> Gotham PD intercepted this email sent to Deputy Commissioner David Mitchell the night before his death. The body is empty. No attachment. No signature. Looks like a mistake. The Riddler never makes mistakes.

**File:** `riddler_email.eml`

## Solve Path

### Step 1 — Open and inspect all headers
```bash
cat riddler_email.eml
```
Body is empty. Focus on headers.

### Step 2 — Trace the Received chain
```
Received: from unknown (HELO send.anon-relay.onion) (185.220.101.47)
```
Real sending IP: `185.220.101.47` — a Tor exit node. Sender is spoofed.

### Step 3 — Find the suspicious custom headers
```
X-Spam-Token:   UkVORVdBTF9QUk9KRUNUX1BIQVNFX09ORQ==
X-Riddler-Key-A: PE//ZnziIzLXgiMEWGnsOnxHqHo=
X-Riddler-Key-B: I3X0IDrvfiXQrhJeXT3qHiMbr24=
```

### Step 4 — Try the red herring
```bash
echo "UkVORVdBTF9QUk9KRUNUX1BIQVNFX09ORQ==" | base64 -d
# → RENEWAL_PROJECT_PHASE_ONE  (dead end)
```

### Step 5 — Decode Key-A and Key-B
Both are Base64 but decode to binary garbage. They need an XOR key.

### Step 6 — Find the key in Message-ID
```
Message-ID: <4f2a9c13.0e8b.4d57.a3f1.7c6d2b0e9841@gotham-city.gov>
```
Strip dots from local part:
```
4f2a9c130e8b4d57a3f17c6d2b0e9841
```
This is the 16-byte XOR key.

### Step 7 — XOR decode both halves
```python
import base64

key = bytes.fromhex("4f2a9c130e8b4d57a3f17c6d2b0e9841")

def xor_decode(b64_str, key):
    data = base64.b64decode(b64_str)
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode()

part1 = xor_decode("PE//ZnziIzLXgiMEWGnsOnxHqHo=", key)
part2 = xor_decode("I3X0IDrvfiXQrhJeXT3qHiMbr24=", key)
print(part1 + part2)
```

## Flag
```
securinets_isgt{3m4il_h34d3rs_n3v3r_l13}
```

## What This Teaches
- Email header forensics and Received chain analysis
- Sender spoofing via relay
- XOR encoding with key derived from another header field
- The difference between standard and custom `X-` headers

---

# Challenge 3 — "Wrong Timezone"
**Points:** 350 (dynamic, min 75) | **Difficulty:** Medium

## Description
> *"He was everywhere that night. Three photos. One document. All from the gala. Or were they? One of these things is not like the others. Find the ghost — and hear what it whispers."*
>
> Gotham PD forensics recovered 4 files from a drive seized at Edward Nashton's apartment. Metadata looks consistent. Look closer.

**Files:** `wayne_tower_ext.jpg`, `gala_interior.jpg`, `rooftop_figure.jpg`, `renewal_notes.docx`

## Solve Path

### Step 1 — Extract EXIF from all files
```bash
exiftool wayne_tower_ext.jpg gala_interior.jpg rooftop_figure.jpg
exiftool renewal_notes.docx
```

### Step 2 — Compare timestamps and cameras

| File | DateTime | Make | Model |
|------|----------|------|-------|
| wayne_tower_ext.jpg | 2022:11:03 21:15:00 | Canon | EOS R5 |
| gala_interior.jpg | 2022:11:03 22:03:00 | Canon | EOS R5 |
| **rooftop_figure.jpg** | **2022:11:04 04:22:00** | **Sony** | **Alpha A7 IV** |
| renewal_notes.docx | 2022-11-03 22:45 | — | — |

`rooftop_figure.jpg` is the outlier — different camera, timestamp 6h off, device set to UTC+1 not EST.

### Step 3 — Check ImageDescription (red herring)
```bash
exiftool -ImageDescription rooftop_figure.jpg
# → Uk9PRlRPUF9TVVJWRUlMTEFOQ0VfQVVUSE9SSVpFRA==
echo "Uk9PRlRPUF9TVVJWRUlMTEFOQ0VfQVVUSE9SSVpFRA==" | base64 -d
# → ROOFTOP_SURVEILLANCE_AUTHORIZED  (dead end)
```

### Step 4 — Check less common EXIF fields
```bash
exiftool -u -U rooftop_figure.jpg | grep -E "User Comment|Image Unique"
```
Output:
```
User Comment    : 7365637572696e6574735f697367747b74316d337a30
Image Unique ID : 6e33735f6233747261795f3376336e5f6768307374737d
```

### Step 5 — Hex decode both fields and concatenate
```python
part1 = bytes.fromhex("7365637572696e6574735f697367747b74316d337a30").decode()
part2 = bytes.fromhex("6e33735f6233747261795f3376336e5f6768307374737d").decode()
print(part1 + part2)
```

## Flag
```
securinets_isgt{t1m3z0n3s_b3tray_3v3n_gh0sts}
```

## What This Teaches
- EXIF metadata extraction and cross-file comparison
- Timezone forensics — device timezone exposes origin
- Multiple EXIF field types beyond ImageDescription
- Red herring recognition — first find isn't always the answer

---

# Challenge 4 — "The Loyal Printer"
**Points:** 500 (dynamic, min 100) | **Difficulty:** Hard

## Description
> *"They say a confession unspoken is still a confession. He sent three jobs to the printer. The printer never forgot. Can you read what was never meant to be read?"*
>
> Gotham PD forensic imaging recovered the Windows print spooler directory from Edward Nashton's machine. Three jobs were queued. None ever printed. The spooler remembers everything.

**Files:** `00001.SHD`, `00001.SPL`, `00002.SHD`, `00002.SPL`, `00003.SHD`, `00003.SPL`

## Solve Path

### Step 1 — Understand the file types
- `.SHD` — Shadow file: binary header with job metadata
- `.SPL` — Spool file: actual print data

### Step 2 — Parse each .SHD magic number
```python
import struct

for fname in ["00001.SHD", "00002.SHD", "00003.SHD"]:
    data = open(fname, 'rb').read()
    magic = struct.unpack_from('<I', data, 0)[0]
    print(f"{fname}: magic = 0x{magic:08X}  {'VALID' if magic == 0x400 else 'INVALID'}")
```
Output:
```
00001.SHD: 0x00000400  VALID
00002.SHD: 0x00000400  VALID
00003.SHD: 0xDEADBEEF  INVALID ← corrupt, discard
```

### Step 3 — Check SPL files
- `00001.SPL` — valid EMF stream, contains decoy: `securinets_isgt{f4k3_spl_str1ng}`
- `00002.SPL` — truncated, contains decoy: `securinets_isgt{c0rrupt_spl_d3c0y}`
- `00003.SHD` DocName — contains decoy: `securinets_isgt{wr0ng_j0b_wr0ng_ans}`

**All three visible flags are decoys.**

### Step 4 — Parse metadata fields of valid job 00001
```python
import struct

def read_wstr(data, offset):
    length = struct.unpack_from('<H', data, offset)[0]
    offset += 2
    if length == 0: return "", offset
    s = data[offset:offset+length].decode('utf-16-le', errors='replace')
    return s, offset + length

data   = open("00001.SHD", 'rb').read()
offset = 48  # skip fixed header

fields = ["UserName","MachineName","PrinterName","DocName",
          "DataType","PrintProcessor","Parameters","DriverName"]
for field in fields:
    val, offset = read_wstr(data, offset)
    print(f"{field}: {val!r}")
```
Output:
```
UserName    : 'sp1ll'
MachineName : 's3cr3ts'
PrinterName : 'GCPD-EVIDENCE-PRN-04'
DocName     : 'pr1nt_j0bs'
```

### Step 5 — Assemble flag from metadata fields
```
securinets_isgt{ DocName _ UserName _ MachineName }
             = { pr1nt_j0bs _ sp1ll _ s3cr3ts }
```

**Key insight:** `strings` on SHD files shows nothing because strings are UTF-16LE. Use `strings -e l` or write a proper parser.

## Flag
```
securinets_isgt{pr1nt_j0bs_sp1ll_s3cr3ts}
```

## What This Teaches
- Windows print spooler forensics (real investigative technique)
- Binary format parsing with `struct`
- UTF-16LE string encoding
- Triaging corrupt vs valid artifacts before analysis
- Not trusting content in corrupt records

---

# Challenge 5 — "The Borrowed Session"
**Points:** 400 (dynamic, min 100) | **Difficulty:** Medium/Hard

## Description
> *"He didn't break the door. He walked through it. Someone left it open. Find the moment the ghost stepped in — and read what it carried."*
>
> Gotham City Hall's internal portal was active the night of the Renewal Gala. Three officials were logged in. One of their sessions was stolen. Two artifacts. One story.

**Files:** `access.log`, `session_cookies.bin`

## Solve Path

### Step 1 — Profile users in access.log

| User | Pattern |
|------|---------|
| gcolson | Single IP, Firefox, clean session |
| fsavage | IP changes (10.0.0.88 → 203.0.113.91) but UA stays Chrome — VPN, not hijack |
| dmitchell | Normal Chrome from 192.168.1.45 until... |

### Step 2 — Spot the hijack
```bash
grep "dmitchell" access.log | awk '{print $1, $4, $NF}' | head -20
```
At `23:51:03`:
```
192.168.1.45  → Chrome/106   (last legit)
185.220.101.47 → curl/7.85.0  (HIJACK — IP + UA both change)
```

Attacker IP: **`185.220.101.47`**

### Step 3 — Parse session_cookies.bin
Binary format:
```
Magic:   "GCPD-SESS\x00"  (10 bytes)
Version: \x01\x00         (2 bytes)
Count:   \x03\x00         (2 bytes)
Entries: name_len(2) + name + value_len(2) + value
```

```python
import struct

data = open("session_cookies.bin", "rb").read()
pos  = 14  # skip header

for _ in range(3):
    name_len = struct.unpack_from('<H', data, pos)[0]; pos += 2
    name     = data[pos:pos+name_len].decode(); pos += name_len
    val_len  = struct.unpack_from('<H', data, pos)[0]; pos += 2
    val      = data[pos:pos+val_len]; pos += val_len
    print(f"{name}: {val.hex()[:40]}...")
```
Three entries: `session_id`, `auth_token`, `csrf_token`

### Step 4 — XOR decode auth_token with attacker IP
```python
key  = bytes(int(x) for x in "185.220.101.47".split('.'))
# key = b'\xb9\xdc\x65\x2f'

flag = bytes(b ^ key[i % 4] for i, b in enumerate(val)).decode()
print(flag)
```

## Flag
```
securinets_isgt{s3ss10n_t0k3ns_d0nt_l13}
```

## What This Teaches
- Apache log format parsing and session hijacking detection
- IP change vs UA change — both required to confirm hijack
- Binary file parsing with struct
- XOR decoding with a key derived from another artifact
- Multi-artifact correlation

---

# Challenge 6 — "The Insider's Routine"
**Points:** 450 (dynamic, min 100) | **Difficulty:** Medium/Hard

## Description
> *"One of them was always there. Not when the others were watching. Every night. Same time. Same door. Routine is the enemy of secrecy — and the friend of those who know how to read it."*
>
> Gotham City server. Five authorized users. One of them has been leaking the Renewal files for two weeks. No malware. No exploits. Just legitimate commands. The pattern is there. Find it.

**Files:** `auth.log`, `cron.log`, `bash_histories/.bash_history_{user}`

## Solve Path

### Step 1 — Profile login patterns from auth.log
```bash
grep "Accepted" auth.log | awk '{print $9, substr($11,1,5)}' | sort | uniq -c | sort -rn
```

| User | Pattern |
|------|---------|
| jgordon | 08:00–09:00, weekdays only |
| bwayne | Irregular, 9AM–10PM |
| hdent | Normal hours + **2 late nights** (23:00, days 3 & 9) |
| lkane | Sparse, 10:00–11:00 |
| **enashton** | **03:00 AM, every single night, 14/14 days** |

### Step 2 — Corroborate with cron.log
```bash
grep "enashton" cron.log
```
Two entries fire every night:
- `03:01` — `/usr/local/bin/system-cleanup` (disguised)
- `03:05` — `/tmp/.maintenance.sh` ← hidden script in /tmp, highly suspicious

### Step 3 — Inspect enashton's bash history
Separate normal commands from suspicious ones:

**Suspicious commands in chronological order:**
```
inotifywait -m /etc/passwd -e access -e modify
nmap -sn 10.0.0.0/24
ss -tlnp | tee /tmp/.cache_dump
id
du -sh /home/* | sort -rh
env | grep -i pass
rsync -avz /etc/ /tmp/.bak/
kill -0 $(cat /var/run/syslog.pid)
netstat -an | grep ESTABLISHED
openssl enc -d -aes-256-cbc -in /tmp/.x -out /tmp/.y -k r3n3wal
who -a | tee /tmp/.who_log
stat /var/log/auth.log
```

### Step 4 — Extract first letters
```
i-n-s-i-d-e-r-k-n-o-w-s
```

**Note:** `r3n3wal` (the openssl key) is a narrative red herring — links to the Renewal case but is not the flag.

## Flag
```
securinets_isgt{insiderknows}
```

## What This Teaches
- Behavioral log analysis — pattern recognition over time
- Distinguishing anomaly from confirmation (hdent's 2 late nights vs enashton's 14)
- Cron log forensics — spotting persistence mechanisms
- LOLBins (Living off the Land) — malicious use of legitimate tools
- Multi-source correlation: auth + cron + shell history together

---

# Challenge 7 — "Dead Letter Office"
**Points:** 500 (dynamic, min 150) | **Difficulty:** Hard

## Description
> *"He tried to erase it. Three drafts. Three times he changed his mind. Then he deleted everything. But a disk never truly forgets. Find what he buried — all three pieces. Only together do they confess."*
>
> Gotham PD forensics imaged a partition from Nashton's workstation minutes before it was wiped. The visible filesystem is nearly empty. What you need was deleted. Recover it.

**File:** `gotham_partition.img`

## Solve Path

### Step 1 — Identify the filesystem
```bash
file gotham_partition.img
# → Linux rev 1.0 ext4 filesystem data, volume name "GOTHAM-SRV-01"
```

### Step 2 — List visible files
```bash
echo "ls /" | debugfs gotham_partition.img
# → readme.txt  lost+found
```

### Step 3 — Read the readme hint
```bash
echo "cat readme.txt" | debugfs gotham_partition.img
```
Contains: `Hint: R0VUIFRIRSBEQU1QIE5PVCBUSEUgQ09OVEVOVFM=`
```bash
echo "R0VUIFRIRSBEQU1QIE5PVCBUSEUgQ09OVEVOVFM=" | base64 -d
# → GET THE DAMP NOT THE CONTENTS
```
"Damp" = metadata. Check extended attributes, not just file content.

### Step 4 — Find deleted inodes
```bash
echo "lsdel" | debugfs gotham_partition.img
```
4 deleted inodes: 13, 14, 15, 16

### Step 5 — Recover each inode
```bash
echo "cat <13>" | debugfs gotham_partition.img  # confession_v1 → Fragment: d3l3t3d_
echo "cat <14>" | debugfs gotham_partition.img  # confession_v2 → Fragments: d3l3t3d_ but_n3v3r
echo "cat <15>" | debugfs gotham_partition.img  # confession_v3 → CORRUPTED last part
echo "cat <16>" | debugfs gotham_partition.img  # notes.txt → lore only
```

### Step 6 — Check extended attributes on inode 15
```bash
echo "ea_list <15>" | debugfs gotham_partition.img
# Extended attributes:
#   user.fragment (5) = "_g0n3"
```

### Step 7 — Reconstruct
```
v1 fragment:    d3l3t3d_
v2 adds:        but_n3v3r
v3 xattr:       _g0n3
Combined:       d3l3t3d_but_n3v3r_g0n3
```

## Flag
```
securinets_isgt{d3l3t3d_but_n3v3r_g0n3}
```

## What This Teaches
- ext4 filesystem structure and inode recovery
- `debugfs` — lsdel, cat by inode number
- Extended attributes (xattrs) — metadata not in file content
- Why `strings` finds 2/3 fragments but misses xattrs
- Deleted ≠ gone on most filesystems

---

# Challenge 8 — "The Ghost Process"
**Points:** 550 (dynamic, min 150) | **Difficulty:** Hard

## Description
> *"It was there. It was always there. But you couldn't see it. The list lied — not by adding a name, but by removing one. Find what the kernel tried to forget."*
>
> Gotham PD captured a memory image from a city server during the Renewal investigation. Standard process listing shows nothing unusual. But something is running. Something that shouldn't exist. Find the ghost.

**File:** `gotham_memdump.dmp.gz` (Windows x64 memory dump, 64MB — decompress first)

## Solve Path

### Step 1 — Identify the dump
```bash
gunzip gotham_memdump.dmp.gz
python3 -c "print(open('gotham_memdump.dmp','rb').read(8))"
# → b'PAGEDU64'  ← Windows 64-bit crash dump
```

### Step 2 — Run pslist (walks ActiveProcessLinks)
```bash
vol -f gotham_memdump.dmp windows.pslist
```
Shows 12 processes. Nothing obviously wrong.

### Step 3 — Run psscan (raw memory pool tag scan)
```bash
vol -f gotham_memdump.dmp windows.psscan
```
Shows **13 processes** — one more than pslist:
```
0x28000   1337   720   gcpd_upd.exe   ← NOT IN PSLIST
```

**PID 1337 `gcpd_upd.exe` appears in psscan but not pslist.**
This is DKOM — Direct Kernel Object Manipulation. The process was unlinked from `ActiveProcessLinks` to hide from list-walking tools.

### Step 4 — Extract command line of PID 1337
```bash
vol -f gotham_memdump.dmp windows.cmdline --pid 1337
```
Output:
```
C:\Windows\Temp\gcpd_upd.exe --exfil --key securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}
```

### Alternative — no Volatility
```bash
python3 parse_memdump_SOLUTION.py gotham_memdump.dmp --psscan
python3 parse_memdump_SOLUTION.py gotham_memdump.dmp --cmdline 1337
```

## Flag
```
securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}
```

## What This Teaches
- Windows EPROCESS structure and ActiveProcessLinks
- DKOM rootkit technique — how processes hide from the kernel list
- pslist vs psscan — the fundamental difference in approach
- Pool tag scanning as a rootkit evasion bypass
- Why absence from the list is itself evidence

---

# Challenge 9 — "Slow Exfil"
**Points:** 500 (dynamic, min 150) | **Difficulty:** Hard

## Description
> *"He didn't send a file. He didn't write a message. He asked questions — sixty of them — one every six minutes, for four hours. And in the asking, everything was said."*
>
> Gotham PD captured traffic from Mitchell's workstation the night of the gala. Sixty outbound HTTPS connections. Nothing in the payloads — they're encrypted. But the destination names were chosen very carefully. Read between the handshakes.

**File:** `slow_exfil.pcap`

## Solve Path

### Step 1 — Survey the traffic
```bash
tshark -r slow_exfil.pcap -Y "tls.handshake.type == 1" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name \
  | sort | uniq -c | sort -rn
```
Two domain families appear:
- `*.cdn-update.net` → always to `185.220.101.47` (40 packets)
- `*.cdn-static.net` → to various CDN IPs (20 packets — noise)

### Step 2 — Decode the noise (red herring)
```bash
echo "dXBkYXRl" | base64 -d
# → update
```
All `cdn-static.net` subdomains decode to plain English words. These are noise.

### Step 3 — Extract signal packets in timestamp order
```bash
tshark -r slow_exfil.pcap \
  -Y "tls.handshake.type == 1 && ip.dst == 185.220.101.47" \
  -T fields -e frame.time_epoch \
  -e tls.handshake.extensions_server_name \
  | sort -n
```

### Step 4 — Decode each SNI subdomain
```python
import subprocess, base64

result = subprocess.run([
    'tshark', '-r', 'slow_exfil.pcap',
    '-Y', 'tls.handshake.type == 1 && ip.dst == 185.220.101.47',
    '-T', 'fields', '-e', 'frame.time_epoch',
    '-e', 'tls.handshake.extensions_server_name'
], capture_output=True, text=True)

def pad(s): return s + '=' * (-len(s) % 4)

flag = ""
packets = sorted(
    (line.split('\t') for line in result.stdout.strip().splitlines()),
    key=lambda x: float(x[0])
)
for ts, sni in packets:
    subdomain = sni.split('.')[0]
    flag += base64.b64decode(pad(subdomain)).decode()

print(flag)
```

Or use the provided solver:
```bash
python3 slow_exfil_solver_SOLUTION.py slow_exfil.pcap
```

## Flag
```
securinets_isgt{sn1_3xf1l_sl0w_and_st34lthy}
```

## What This Teaches
- TLS SNI field forensics
- Covert channel detection in protocol metadata
- Signal vs noise — filtering by destination IP before decoding
- tshark field extraction
- Why encrypted traffic still leaks information through metadata

---

# Challenge 10 — "Palimpsest"
**Points:** 600 (dynamic, min 200) | **Difficulty:** Hard

## Description
> *"A palimpsest: a manuscript where the old writing shows through the new. They thought they could erase me. They thought sanitizing the document would sanitize the truth. Read what was written first. Then read it again. The confession was always there."*
>
> Gotham PD recovered this PDF from the Mayor's office servers. It appears blank — just a Renewal Initiative placeholder. Three rounds of sanitization were applied before it was filed. None of them actually erased anything. Peel back the layers.

**File:** `confession_redacted.pdf`

## Solve Path

### Step 1 — Open the PDF
Shows: *"GOTHAM CITY - OFFICE OF THE MAYOR / RENEWAL INITIATIVE / This document is intentionally blank."*

### Step 2 — Count %%EOF markers
```bash
grep -c "%%EOF" confession_redacted.pdf
# → 4
```
4 markers = 1 original body + 3 incremental updates. PDF incremental updates never erase — they only append.

### Step 3 — Find the original xref
```bash
grep -a "startxref" confession_redacted.pdf
```
Four startxref values. The **smallest** is the original: offset `1084`.

### Step 4 — Extract all versions of object 3 (Info/metadata)
```python
import re

raw  = open('confession_redacted.pdf', 'rb').read()
objs = re.findall(rb'3 0 obj.*?endobj', raw, re.DOTALL)
for i, o in enumerate(objs):
    author = re.search(rb'/Author \((.+?)\)', o)
    print(f"Version {i+1}: {author.group(1).decode() if author else 'N/A'}")
```
Output:
```
Version 1: pdf_l4y3rs        ← ORIGINAL — FLAG PART 1
Version 2: E. Nashton - REDACTED
Version 3: Office of the Mayor
Version 4: GCPD Records Office
```

### Step 5 — Decompress all content streams
```python
import zlib, re

raw = open('confession_redacted.pdf', 'rb').read()
for i, m in enumerate(re.finditer(rb'stream\r?\n(.*?)\r?\nendstream', raw, re.DOTALL)):
    try:
        dec = zlib.decompress(m.group(1)).decode('latin-1')
        if 'Authorization' in dec:
            print(f"Stream {i+1}:\n{dec}")
    except: pass
```
Stream 1 (original) contains:
```
Authorization code: 6e337633725f7472756c795f3372347333
```

### Step 6 — Hex decode the authorization code
```python
bytes.fromhex("6e337633725f7472756c795f3372347333").decode()
# → n3v3r_truly_3r4s3   ← FLAG PART 2
```

### Step 7 — Reconstruct
```
Part 1 (Author, original):   pdf_l4y3rs
Part 2 (stream hex decoded): n3v3r_truly_3r4s3
Flag: securinets_isgt{pdf_l4y3rs_n3v3r_truly_3r4s3}
```

Or use the provided solver:
```bash
python3 palimpsest_solver_SOLUTION.py confession_redacted.pdf
```

## Flag
```
securinets_isgt{pdf_l4y3rs_n3v3r_truly_3r4s3}
```

## What This Teaches
- PDF incremental update structure
- How "sanitized" PDFs leak original content
- xref table chain navigation
- FlateDecode stream decompression
- Why PDF redaction requires specialized tools — not just overwriting
- Real-world relevance: this is how classified document leaks happen

---

## 📊 Challenge Summary

| # | Name | Points | Min | Flag |
|---|---|---|---|---|
| 1 | The Screenshot That Shouldn't Exist | 200 | 50 | *(your flag)* |
| 2 | The Empty Email | 300 | 75 | `securinets_isgt{3m4il_h34d3rs_n3v3r_l13}` |
| 3 | Wrong Timezone | 350 | 75 | `securinets_isgt{t1m3z0n3s_b3tray_3v3n_gh0sts}` |
| 4 | The Loyal Printer | 500 | 100 | `securinets_isgt{pr1nt_j0bs_sp1ll_s3cr3ts}` |
| 5 | The Borrowed Session | 400 | 100 | `securinets_isgt{s3ss10n_t0k3ns_d0nt_l13}` |
| 6 | The Insider's Routine | 450 | 100 | `securinets_isgt{insiderknows}` |
| 7 | Dead Letter Office | 500 | 150 | `securinets_isgt{d3l3t3d_but_n3v3r_g0n3}` |
| 8 | The Ghost Process | 550 | 150 | `securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}` |
| 9 | Slow Exfil | 500 | 150 | `securinets_isgt{sn1_3xf1l_sl0w_and_st34lthy}` |
| 10 | Palimpsest | 600 | 200 | `securinets_isgt{pdf_l4y3rs_n3v3r_truly_3r4s3}` |

**Total max points: 4350**
