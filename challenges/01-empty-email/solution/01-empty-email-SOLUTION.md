# Challenge 2 — "The Empty Email"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"I sent him a message. He never read it.*
> *Or did he? Maybe he read everything*
> *and understood nothing.*
> *Can you do better, detective?"*
>
> Gotham PD intercepted this email sent to Deputy Commissioner David Mitchell
> the night before his death. The body is empty. No attachment. No signature.
> Looks like a mistake.
>
> The Riddler never makes mistakes.
>
> **Find who really sent it — and what they left behind.**

**File:** `riddler_email.eml`
**Category:** Forensics
**Difficulty:** Medium
**Points:** 300

---

## 🎯 Intended Solve Path

### Step 1 — Open the .eml and notice the empty body
Players open the file in a mail client (Thunderbird) or a text editor.
Body is completely empty. No visible content whatsoever.

### Step 2 — Read the headers carefully
The `From:` field shows `no-reply@gotham-city.gov` — looks legitimate.
But the `Received:` chain tells a different story:

```
Received: from unknown (HELO send.anon-relay.onion) (185.220.101.47)
```

The real sending IP is `185.220.101.47` — a Tor exit node, not a city server.
The email was **relayed through** the city mail server to appear legitimate.

### Step 3 — Spot the suspicious custom headers
Two headers stand out:
- `X-Spam-Token: UkVORVdBTF9QUk9KRUNUX1BIQVNFX09ORQ==`
- `X-Riddler-Key: c2VjdXJpbmV0c19pc2d0ezNtNGlsX2gzNGQzcnNfbjN2M3JfbDEzfQ==`

Both look like Base64. Players will likely try both.

### Step 4 — Decode both
```bash
echo "UkVORVdBTF9QUk9KRUNUX1BIQVNFX09ORQ==" | base64 -d
# → RENEWAL_PROJECT_PHASE_ONE   (red herring — no flag)

echo "c2VjdXJpbmV0c19pc2d0ezNtNGlsX2gzNGQzcnNfbjN2M3JfbDEzfQ==" | base64 -d
# → securinets_isgt{3m4il_h34d3rs_n3v3r_l13}
```

The `X-Spam-Token` is a deliberate red herring — decodes to a Riddler lore
string that sounds significant but contains no flag.
The flag lives in `X-Riddler-Key`.

---

## 🚩 Flag
```
securinets_isgt{3m4il_h34d3rs_n3v3r_l13}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `From: no-reply@gotham-city.gov` | Legitimate city email | Forged sender |
| `Message-ID: <4f2a9c1...>` | Looks like encoded hex | Valid RFC 5322 format, meaningless |
| `X-Spam-Token` | Base64 flag candidate | Decodes to lore string, dead end |
| `X-MS-Exchange-Organization-SCL: -1` | Trusted internal mail marker | Faked to bypass spam filters |

---

## 🛠️ Tools Players Might Use
- Text editor (minimum viable)
- Thunderbird / any mail client
- `base64 -d` on command line
- Python: `import base64; base64.b64decode(...)`
- MXToolbox header analyzer
- `emlAnalyzer` tool

---

## 💡 Hint (optional, costs points)
> *"Not all headers are born equal.*
> *The standard ones follow rules.*
> *The custom ones follow no one."*
> — Look for headers that start with `X-` and aren't standard mail headers.

---

## 📚 What This Teaches
- Email header structure and the Received chain
- How sender spoofing works through relay servers
- `X-` custom header awareness
- Base64 recognition and decoding
- The difference between what an email *looks* like and what it *contains*
