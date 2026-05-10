# 🦇 Securinets ISGT — Forensics CTF
### *"If you are justice, please do not lie. What is the war on crime, if you don't know who the criminals are?"*

---

## Overview

This repository contains the **forensics challenge set** for **Securinets ISGT**, themed around *The Riddler* from *The Batman* (2022). Ten challenges covering a broad range of digital forensics disciplines, designed for intermediate-to-advanced CTF players.

Every challenge is framed as a piece of evidence from the Gotham City investigation into Edward Nashton — email artifacts, disk images, memory dumps, network captures, and more. The Riddler never makes mistakes. The evidence is always there. You just have to know where to look.

---

## 🧩 Challenge Set

| # | Name | Category | Points | Difficulty |
|---|---|---|---|---|
| 01 | The Screenshot That Shouldn't Exist | Visual + Log Correlation | 200 | ⭐ Easy |
| 02 | The Empty Email | Email Forensics | 300 | ⭐⭐ Medium |
| 03 | Wrong Timezone | Metadata Analysis | 350 | ⭐⭐ Medium |
| 04 | The Loyal Printer | Windows Artifacts | 500 | ⭐⭐⭐ Hard |
| 05 | The Borrowed Session | Web Log + Binary | 400 | ⭐⭐⭐ Hard |
| 06 | The Insider's Routine | Behavioral Analysis | 450 | ⭐⭐⭐ Hard |
| 07 | Dead Letter Office | Filesystem Recovery | 500 | ⭐⭐⭐ Hard |
| 08 | The Ghost Process | Memory Forensics | 550 | ⭐⭐⭐⭐ Hard |
| 09 | Slow Exfil | Network Forensics | 500 | ⭐⭐⭐⭐ Hard |
| 10 | Palimpsest | Document Forensics | 600 | ⭐⭐⭐⭐ Hard |

**Total max points: 4350** (dynamic scoring — values decrease with each solve)

---

## 🏆 Scoring

Challenges use **dynamic scoring**:

| Tier | Challenges | Decay Model | Min Points |
|---|---|---|---|
| Entry | 01, 02, 03 | Linear | 50–75 |
| Mid | 04, 05, 06 | Linear | 100 |
| Hard | 07, 08, 09, 10 | Logarithmic | 150–200 |

Points decrease as more teams solve a challenge. First blood rewards fast, accurate play. Harder challenges flatten out — the 20th solver of Ghost Process still earns meaningful points.

---

## 📁 Repository Structure

```
securinets-isgt-forensics/
│
├── challenges/
│   ├── 01-screenshot/
│   │   ├── challenge/          ← files given to players
│   │   └── solution/           ← SOLUTION.md + scripts (private)
│   ├── 02-empty-email/
│   ├── 03-wrong-timezone/
│   ├── 04-loyal-printer/
│   ├── 05-borrowed-session/
│   ├── 06-insiders-routine/
│   ├── 07-dead-letter-office/
│   ├── 08-ghost-process/
│   ├── 09-slow-exfil/
│   └── 10-palimpsest/
│
└── docs/
    ├── all_solutions.md        ← complete writeups for all challenges
    └── scoring.md              ← dynamic scoring configuration
```

> **Note:** The `solution/` directories are kept in this repository for organizer reference. If making this repo public after the competition, solutions should be moved to a separate branch or released post-event.

---

## 🛠️ Tools Required

Players will need some or all of the following depending on which challenges they attempt:

**General**
- Python 3.x
- `strings`, `file`, `xxd`, `hexdump`
- `base64`, `openssl`

**Email**
- Any text editor or mail client (Thunderbird)

**Metadata / Image**
- `exiftool`
- Python `Pillow`

**Filesystem**
- `debugfs` (e2fsprogs)
- `sleuthkit` (`fls`, `icat`, `fsstat`)
- `extundelete` (optional)

**Network**
- Wireshark / `tshark`
- Python `struct`, `socket`

**Memory**
- Volatility 3 (`pip install volatility3`)
- Python `struct`

**Document**
- Python `zlib`, `re`
- `pdf-parser.py` (Didier Stevens, optional)
- `peepdf` (optional)

**Windows Artifacts**
- Python `struct`
- `strings -e l` (little-endian UTF-16)

---

## 🎯 Disciplines Covered

| Discipline | Challenges |
|---|---|
| Email Header Forensics | 01 |
| EXIF / File Metadata | 02 |
| Windows Print Spooler | 03 |
| Web Log Analysis / Binary Parsing | 04 |
| Behavioral Log Analysis | 05 |
| ext4 Filesystem Recovery | 06 |
| Memory Forensics (DKOM) | 07 |
| Network Forensics / TLS SNI | 08 |
| PDF Internal Structure | 09 |

---

## 🔒 Flag Format

```
securinets_isgt{...}
```

All flags follow this format. Case sensitive.

---

## 📖 Challenge Descriptions


### 01 — The Empty Email
> *"I sent him a message. He never read it. Or did he? Maybe he read everything and understood nothing. Can you do better, detective?"*

An intercepted email with an empty body. The real message is in the headers — but reading it requires more than a Base64 decoder.

---

### 02 — Wrong Timezone
> *"He was everywhere that night. Three photos. One document. All from the gala. Or were they? One of these things is not like the others. Find the ghost — and hear what it whispers."*

Four files recovered from Nashton's drive. Metadata looks consistent. One file was taken on a different device in a different timezone — and it carries a message in fields most analysts never check.

---

### 03 — The Loyal Printer
> *"They say a confession unspoken is still a confession. He sent three jobs to the printer. The printer never forgot. Can you read what was never meant to be read?"*

Three Windows print spool file pairs. Three decoy flags. One valid job. The flag is not in the print data — it's in the metadata of the only job worth trusting.

---

### 04 — The Borrowed Session
> *"He didn't break the door. He walked through it. Someone left it open. Find the moment the ghost stepped in — and read what it carried."*

Apache access logs show a session hijack. Identifying it is step one. Step two requires a binary artifact and the knowledge to decode it.

---

### 05 — The Insider's Routine
> *"One of them was always there. Not when the others were watching. Every night. Same time. Same door. Routine is the enemy of secrecy."*

Five users. Fourteen days. Auth logs, cron logs, and bash histories. One user is malicious — using only legitimate commands. Find them. Then read what their hands spelled.

---

### 06 — Dead Letter Office
> *"He tried to erase it. Three drafts. Three times he changed his mind. Then he deleted everything. But a disk never truly forgets."*

An ext4 disk image with an almost empty filesystem. Four deleted inodes. Three confession drafts. One piece of the flag lives somewhere most recovery tools will never surface.

---

### 07 — The Ghost Process
> *"It was there. It was always there. But you couldn't see it. The list lied — not by adding a name, but by removing one."*

A Windows x64 memory dump. Standard process listing shows nothing unusual. A rootkit used DKOM to unlink a process from the kernel list. Pool tag scanning finds what the list tried to forget.

---

### 08 — Slow Exfil
> *"He didn't send a file. He didn't write a message. He asked questions — sixty of them — one every six minutes, for four hours. And in the asking, everything was said."*

Sixty TLS connections. Encrypted payloads. But the destination names were chosen very carefully. Filter, sort, decode, concatenate. The flag was never in the data — it was in the asking.

---

### 9 — Palimpsest
> *"A palimpsest: a manuscript where the old writing shows through the new. They thought sanitizing the document would sanitize the truth. The confession was always there."*

A PDF that appears blank. Three rounds of incremental sanitization. None of them erased anything. The original confession is still physically present — split across two layers that most analysts never look for.

---


## 🕵️ Good luck, detective.

*"I'm the one who showed this city who it truly is."*
— Edward Nashton
