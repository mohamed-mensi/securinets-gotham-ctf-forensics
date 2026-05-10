# Challenge 3 — "Wrong Timezone"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"He was everywhere that night.*
> *Three photos. One document. All from the gala.*
> *Or were they?*
> *One of these things is not like the others.*
> *Find the ghost — and hear what it whispers."*
>
> Gotham PD forensics recovered 4 files from a drive seized at
> Edward Nashton's apartment. Three photos from the night of the
> Renewal Gala, and a set of notes. Metadata looks consistent.
>
> Look closer.

**Files:** `wayne_tower_ext.jpg`, `gala_interior.jpg`, `rooftop_figure.jpg`, `renewal_notes.docx`
**Category:** Forensics
**Difficulty:** Medium
**Points:** 350

---

## 🎯 Intended Solve Path

### Step 1 — Extract all metadata
Players run ExifTool (or equivalent) on all 4 files:

```bash
exiftool wayne_tower_ext.jpg gala_interior.jpg rooftop_figure.jpg
exiftool renewal_notes.docx
```

Or manually with Python:
```python
from PIL import Image
img = Image.open("rooftop_figure.jpg")
exif = img.getexif()
for tag, val in exif.items():
    print(tag, val)
```

### Step 2 — Compare timestamps

| File | DateTime | Make | Model |
|------|----------|------|-------|
| wayne_tower_ext.jpg | 2022:11:03 21:15:00 | Canon | EOS R5 |
| gala_interior.jpg | 2022:11:03 22:03:00 | Canon | EOS R5 |
| **rooftop_figure.jpg** | **2022:11:04 04:22:00** | **Sony** | **Alpha A7 IV** |
| renewal_notes.docx | Created: 2022-11-03 22:45 | — | — |

`rooftop_figure.jpg` stands out: timestamp is 6+ hours after the others,
AND it comes from a different device (Sony vs Canon).

### Step 3 — Reason about the timezone
If `rooftop_figure.jpg` were taken at 04:22 **EST**, that's 09:22 UTC —
way outside the gala timeline.

But if the device was set to **UTC+1** (CET), then:
`04:22 UTC+1 = 03:22 UTC = 22:22 EST`

That fits perfectly within the gala night timeline.
The device's clock was set to a **European timezone** — betraying that
it's a different device from a different location, or deliberately misconfigured.

### Step 4 — Inspect the outlier file's metadata
The `ImageDescription` EXIF field of `rooftop_figure.jpg` contains:

```
c2VjdXJpbmV0c19pc2d0e3QxbTN6MG4zc19iM3RyYXlfM3Yzbl9naDBzdHN9
```

Decode it:
```bash
echo "c2VjdXJpbmV0c19pc2d0e3QxbTN6MG4zc19iM3RyYXlfM3Yzbl9naDBzdHN9" | base64 -d
# → securinets_isgt{t1m3z0n3s_b3tray_3v3n_gh0sts}
```

---

## 🚩 Flag
```
securinets_isgt{t1m3z0n3s_b3tray_3v3n_gh0sts}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `renewal_notes.docx` Comments field | Base64 string, looks like a flag | Decodes to `GOTHAM_RENEWAL_CLASSIFIED_EYES_ONLY` — dead end |
| Sony Alpha A7 IV vs Canon EOS R5 | Different camera = suspicious | True clue to the outlier, but not the decode step |
| `rooftop_figure.jpg` timestamp | Looks like next-day activity | Actually same night, wrong timezone |
| `.docx` created/modified times | Consistent EST timestamps | Genuine — document was written during the gala |

---

## 🛠️ Tools Players Might Use
- **ExifTool** (most powerful): `exiftool *.jpg`
- **Python Pillow**: `Image.open(f).getexif()`
- **Jeffrey's Exif Viewer** (online)
- **LibreOffice** → File → Properties → Custom (for docx metadata)
- `base64 -d` for decoding

---

## 💡 Hint (optional, costs points)
> *"Every camera knows what time it is.*
> *But whose time? Gotham's? Or somewhere colder?"*
> — Look at timezone offsets, not just the clock values.

---

## 📚 What This Teaches
- EXIF metadata extraction and interpretation
- Timezone forensics — how device timezone exposes origin
- Document metadata (docx core properties)
- Cross-file metadata correlation
- Base64 recognition in unusual fields
