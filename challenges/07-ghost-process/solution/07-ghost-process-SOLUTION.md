# Challenge 8 — "The Ghost Process"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"It was there. It was always there.*
> *But you couldn't see it.*
> *The list lied — not by adding a name,*
> *but by removing one.*
> *Find what the kernel tried to forget."*
>
> Gotham PD captured a memory image from a city server
> during the Renewal investigation. Standard process listing
> shows nothing unusual. But something is running.
> Something that shouldn't exist.
>
> Find the ghost.

**File:** `gotham_memdump.dmp` (Windows x64 memory dump, 64MB)
**Category:** Forensics — Memory
**Difficulty:** Hard
**Points:** 550

---

## 🎯 Intended Solve Path

### Step 1 — Identify the dump
```bash
file gotham_memdump.dmp
# → data (raw dump — check header manually)

python3 -c "print(open('gotham_memdump.dmp','rb').read(8))"
# → b'PAGEDU64'  ← Windows 64-bit crash dump signature
```

### Step 2 — Run pslist
With Volatility 3:
```bash
vol -f gotham_memdump.dmp windows.pslist
```

Output shows 12 processes — all plausible, nothing obviously wrong:
```
PID    PPID   Name
4      0      System
380    4      smss.exe
508    380    csrss.exe
600    380    wininit.exe
720    600    services.exe
728    600    lsass.exe
956    720    svchost.exe      (-k DcomLaunch)
1044   720    svchost.exe      (-k RPCSS)
1312   720    svchost.exe      (-k LocalService)
2388   4      svchost.exe      (-k netsvcs)     ← odd: parent is PID 4 (System)
3120   600    explorer.exe
4012   3120   cmd.exe
```

Note: `svchost.exe` PID 2388 has parent PID 4 (System) instead of services.exe — suspicious, but it's a red herring. Legitimate in some Windows configurations.

### Step 3 — Run psscan

```bash
vol -f gotham_memdump.dmp windows.psscan
```

`psscan` scans **raw physical memory** for the `Proc` pool tag signature — it does NOT walk the `ActiveProcessLinks` linked list. This means it finds EPROCESS structures even if they've been unlinked by a rootkit.

Output shows **13 processes** — one more than pslist:
```
Offset       PID    PPID   Name
0x10000      4      0      System
0x12000      380    4      smss.exe
0x14000      508    380    csrss.exe
0x16000      600    380    wininit.exe
0x18000      720    600    services.exe
0x1A000      728    600    lsass.exe
0x1C000      956    720    svchost.exe
0x1E000      1044   720    svchost.exe
0x20000      1312   720    svchost.exe
0x22000      2388   4      svchost.exe
0x24000      3120   600    explorer.exe
0x26000      4012   3120   cmd.exe
0x28000      1337   720    gcpd_upd.exe    ← NOT IN PSLIST
```

**PID 1337 `gcpd_upd.exe` is present in psscan but absent from pslist.**
This is the textbook signature of DKOM (Direct Kernel Object Manipulation) — the process was unlinked from `ActiveProcessLinks` to hide from tools that walk the list.

### Step 4 — Extract command line of PID 1337

```bash
vol -f gotham_memdump.dmp windows.cmdline --pid 1337
```

Or with the custom parser (see solution tools):
```bash
python3 parse_memdump.py gotham_memdump.dmp --cmdline 1337
```

Output:
```
PID 1337  gcpd_upd.exe
CommandLine: C:\Windows\Temp\gcpd_upd.exe --exfil --key securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}
```

### Step 5 — Extract the flag

```
--key securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}
```

---

## 🚩 Flag
```
securinets_isgt{dk0m_h1d3s_but_p00l_t4gs_d0nt}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `svchost.exe` PID 2388, PPID=4 | Parent is System — very suspicious | Valid edge case in some Windows versions; not the hidden process |
| All `svchost.exe` entries | Multiple instances = suspicious | Normal Windows behavior — services.exe spawns many |
| `cmd.exe` running | Someone has a shell | Legitimate — under explorer.exe (user session) |

---

## 🛠️ Tools Players Might Use

**Volatility 3 (recommended):**
```bash
# Install
pip install volatility3

# Identify profile
vol -f gotham_memdump.dmp windows.info

# List processes via linked list
vol -f gotham_memdump.dmp windows.pslist

# List processes via pool tag scan
vol -f gotham_memdump.dmp windows.psscan

# Get command lines
vol -f gotham_memdump.dmp windows.cmdline

# Compare pslist vs psscan to find hidden processes
vol -f gotham_memdump.dmp windows.psscan | grep -v $(vol -f gotham_memdump.dmp windows.pslist | awk '{print $1}' | tr '\n' '|')
```

**Volatility 2:**
```bash
vol.py -f gotham_memdump.dmp --profile=Win10x64_19041 pslist
vol.py -f gotham_memdump.dmp --profile=Win10x64_19041 psscan
vol.py -f gotham_memdump.dmp --profile=Win10x64_19041 cmdline
```

**Manual/strings approach:**
```bash
strings gotham_memdump.dmp | grep -i "gcpd\|securinets\|exfil"
# Will reveal the hidden process name and flag in raw ASCII strings
# (Easier path — but teaches less)
```

**Custom parser (solution package):**
```bash
python3 parse_memdump.py gotham_memdump.dmp --pslist
python3 parse_memdump.py gotham_memdump.dmp --psscan
python3 parse_memdump.py gotham_memdump.dmp --cmdline 1337
```

---

## 🧠 What DKOM Is (for solution notes/debrief)

Direct Kernel Object Manipulation (DKOM) is a rootkit technique where the attacker modifies kernel data structures in memory directly. The `ActiveProcessLinks` field in each `EPROCESS` structure is a doubly-linked list. By pointing the previous entry's `Flink` and the next entry's `Blink` to skip the target process, the process becomes invisible to any tool that walks this list — including Task Manager, `tasklist`, and Volatility's `pslist`.

However, the EPROCESS structure itself remains in physical memory at its original location. `psscan` exploits this by ignoring the linked list entirely and instead scanning all of physical memory for the `Proc` pool allocation tag that precedes every EPROCESS block. This is why psscan finds what pslist misses.

---

## 💡 Hint (optional, costs points)
> *"The list is a lie.*
> *Lists can be edited. Memory cannot be erased so easily.*
> *Scan deeper than the surface.*
> *What tags were left on the pool?"*
> — `psscan` not `pslist`. Pool tags don't lie.

---

## 📚 What This Teaches
- Windows EPROCESS structure and ActiveProcessLinks
- DKOM rootkit technique — how processes hide from the kernel list
- pslist vs psscan — the fundamental difference in approach
- Pool tag scanning as a rootkit evasion bypass
- Command line argument extraction from memory
- Why "absence from the list" is itself evidence
