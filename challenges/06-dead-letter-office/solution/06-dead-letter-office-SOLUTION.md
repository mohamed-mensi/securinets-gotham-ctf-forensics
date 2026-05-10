# Challenge 7 — "Dead Letter Office"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"He tried to erase it.*
> *Three drafts. Three times he changed his mind.*
> *Then he deleted everything.*
> *But a disk never truly forgets.*
> *Find what he buried — all three pieces.*
> *Only together do they confess."*
>
> Gotham PD forensics imaged a partition from Nashton's workstation
> minutes before it was wiped. The visible filesystem is nearly empty.
> What you need was deleted.
>
> Recover it.

**File:** `gotham_partition.img`
**Category:** Forensics
**Difficulty:** Hard
**Points:** 500

---

## 🎯 Intended Solve Path

### Step 1 — Identify the filesystem
```bash
file gotham_partition.img
# → Linux rev 1.0 ext4 filesystem data, volume name "GOTHAM-SRV-01"

fsstat gotham_partition.img   # (sleuthkit)
# OR
debugfs gotham_partition.img
debugfs: stats
```

### Step 2 — List visible files
```bash
echo "ls /" | debugfs gotham_partition.img
# → readme.txt  lost+found
```

Only `readme.txt` is live. Read it:
```bash
echo "cat readme.txt" | debugfs gotham_partition.img
```
Contains a base64 hint: `R0VUIFRIRSBEQU1QIE5PVCBUSEUgQ09OVEVOVFM=`

```bash
echo "R0VUIFRIRSBEQU1QIE5PVCBUSEUgQ09OVEVOVFM=" | base64 -d
# → GET THE DAMP NOT THE CONTENTS
```

"Damp" = metadata. The flag is NOT in the file content alone — check extended attributes too.

### Step 3 — Find deleted inodes
```bash
echo "lsdel" | debugfs gotham_partition.img
```

Output:
```
Inode  Owner  Mode    Size    Blocks  Time deleted
   13      0  100644   281     1/1    ...
   14      0  100644   393     1/1    ...
   15      0  100644   470     1/1    ...
   16      0  100644   377     1/1    ...
```

4 deleted inodes. Recover all of them.

### Step 4 — Recover each deleted inode
```bash
# Using debugfs
echo "cat <13>" | debugfs gotham_partition.img   # confession_v1
echo "cat <14>" | debugfs gotham_partition.img   # confession_v2
echo "cat <15>" | debugfs gotham_partition.img   # confession_v3
echo "cat <16>" | debugfs gotham_partition.img   # notes.txt

# Using icat (sleuthkit)
icat gotham_partition.img 13
icat gotham_partition.img 14
icat gotham_partition.img 15
icat gotham_partition.img 16
```

### Step 5 — Analyse recovered content

**Inode 13 (confession_v1 — DRAFT 1, oldest):**
```
Fragment: d3l3t3d_
```

**Inode 14 (confession_v2 — DRAFT 2):**
```
Fragments: d3l3t3d_ but_n3v3r
```

**Inode 15 (confession_v3 — FINAL, most recent):**
```
The full record is: d3l3t3d_ but_n3v3r [DATA CORRUPTED: 0xFEFEFEFE]
```
The third fragment is corrupted in the content. But the readme hint said:
**"GET THE DAMP NOT THE CONTENTS"** — check the metadata (extended attributes):

```bash
echo "ea_list <15>" | debugfs gotham_partition.img
# Extended attributes:
#   user.fragment (5) = "_g0n3"

echo "ea_get <15> user.fragment" | debugfs gotham_partition.img
# → _g0n3
```

**Inode 16 (notes.txt):** Lore content only. No flag fragments.

### Step 6 — Reconstruct the flag

Each version adds one fragment:
```
v1 introduces:  d3l3t3d_
v2 adds:        but_n3v3r
v3 xattr has:   _g0n3
```

Concatenate in version order:
```
d3l3t3d_ + but_n3v3r + _g0n3 = d3l3t3d_but_n3v3r_g0n3
```

**Flag:** `securinets_isgt{d3l3t3d_but_n3v3r_g0n3}`

---

## 🚩 Flag
```
securinets_isgt{d3l3t3d_but_n3v3r_g0n3}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `readme.txt` base64 hint | Looks like flag encoding | Decodes to `GET THE DAMP NOT THE CONTENTS` — a metadata hint |
| Inode 16 (`notes.txt`) | 4th deleted file — must have the flag | Lore content only (Maroni, Colson, etc.) |
| v3 content `[DATA CORRUPTED: 0xFEFEFEFE]` | Looks like failed recovery | Deliberate — third fragment is in xattr, not content |
| Version ordering confusion | v2 contains v1's fragment too | Players must diff versions, not just read the last one |

---

## 🛠️ Tools Players Might Use

```bash
# Sleuthkit suite
fsstat gotham_partition.img          # filesystem info
fls -r gotham_partition.img          # file listing including deleted
icat gotham_partition.img <inode>    # recover file by inode

# debugfs (e2fsprogs)
debugfs gotham_partition.img         # interactive
  > lsdel                            # list deleted inodes
  > cat <13>                         # read inode by number
  > ea_list <15>                     # list extended attributes
  > ea_get <15> user.fragment        # read specific xattr

# extundelete
extundelete gotham_partition.img --restore-all

# getfattr (for xattrs on mounted filesystem)
getfattr -n user.fragment <file>

# Raw search
strings gotham_partition.img | grep -E "d3l3t3d|but_n3v3r|fragment"
```

**Key insight:** `strings` will find v1, v2, v3 content fragments but NOT the xattr — that requires debugfs `ea_get` or `getfattr`. Players who only use strings will get 2/3 fragments and be stuck.

---

## 💡 Hint (optional, costs points)
> *"Three drafts. The last one is broken.*
> *But broken content can hide intact metadata.*
> *What is attached to a file is not always inside it."*
> — Extended attributes. `ea_list` in debugfs.

---

## 📚 What This Teaches
- ext4 filesystem structure and inode concepts
- Deleted file recovery via inode table and `lsdel`
- Extended attributes (xattrs) — metadata attached to inodes, not file content
- Differencing file versions to extract incremental information
- The difference between "file content" and "file metadata"
- Why deleted ≠ gone on most filesystems
