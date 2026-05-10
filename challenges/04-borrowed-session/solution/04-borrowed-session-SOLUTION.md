# Challenge 5 — "The Borrowed Session"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"He didn't break the door.*
> *He walked through it.*
> *Someone left it open.*
> *Find the moment the ghost stepped in —*
> *and read what it carried."*
>
> Gotham City Hall's internal portal was active the night of the Renewal Gala.
> Three officials were logged in. One of their sessions was stolen.
> The attacker left traces in every request — but only if you know where to look.
>
> The log format includes a custom `X-Client-Token` field as the last column.

**File:** `access.log`
**Category:** Forensics
**Difficulty:** Medium/Hard
**Points:** 400

---

## 🎯 Intended Solve Path

### Step 1 — Parse the log format
Apache combined log + one extra field:
```
IP - USER [TIMESTAMP] "METHOD PATH HTTP/1.1" STATUS SIZE "REFERER" "UA" "X-CLIENT-TOKEN"
```

Three users active: `dmitchell`, `fsavage`, `gcolson`

### Step 2 — Profile each user's behavior

**gcolson** — clean. Single IP, Firefox, normal session, logout.

**fsavage** — suspicious at first glance:
- Starts from `10.0.0.88` (office)
- Switches to `203.0.113.91` mid-session
- BUT: User-Agent stays identical (Chrome/106) across both IPs
- AND: hits a 403 on `/portal/admin/users` (normal failed access)
- Verdict: VPN switch, not hijacking

**dmitchell** — normal from `192.168.1.45` / Chrome until...

### Step 3 — Spot the hijack moment

```
23:50:59  192.168.1.45    Chrome/106   /portal/dashboard         ← last legit
23:51:03  185.220.101.47  curl/7.85.0  /portal/dashboard         ← HIJACK
```

Two simultaneous signals:
1. **IP change**: `192.168.1.45` → `185.220.101.47` (known Tor exit node)
2. **UA change**: Chrome browser → `curl/7.85.0` (scripted client)

Both signals together = session hijack. Either alone could be coincidence.

### Step 4 — Extract attacker's X-Client-Token values

Filter all `dmitchell` requests from `185.220.101.47`:

```bash
grep "185.220.101.47.*dmitchell" access.log | awk -F'"' '{print $NF}'
```

Output (in timestamp order):
```
c2VjdXJp
bmV0c19p
c2d0e3Mz
c3MxMG5f
dDBrM25z
X2QwbnRfbDEzfQ==
```

### Step 5 — Decode and concatenate

```bash
for tok in c2VjdXJp bmV0c19p c2d0e3Mz c3MxMG5f dDBrM25z X2QwbnRfbDEzfQ==; do
    echo -n "$tok" | base64 -d
done
echo
```

Or Python:
```python
import base64
tokens = ["c2VjdXJp","bmV0c19p","c2d0e3Mz","c3MxMG5f","dDBrM25z","X2QwbnRfbDEzfQ=="]
print("".join(base64.b64decode(t).decode() for t in tokens))
```

Result: `securinets_isgt{s3ss10n_t0k3ns_d0nt_l13}`

---

## 🚩 Flag
```
securinets_isgt{s3ss10n_t0k3ns_d0nt_l13}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `fsavage` IP change | Session hijack candidate | VPN switch — UA never changes, different from attacker pattern |
| Mitchell's `X-Client-Token` at 22:03 | `R0NQRC1BVVRILVNFU1NJT04tVkFMSUQ=` | Decodes to `GCPD-AUTH-SESSION-VALID` — dead end |
| Mitchell's `X-Client-Token` at 22:41 | `UkVORVdBTC1QT1JUQUwtQUNDRVNTLU9L` | Decodes to `RENEWAL-PORTAL-ACCESS-OK` — dead end |
| Referer on 4th attacker request | Base64-looking URL param `?t=R09USEFNX...` | Decodes to `GOTHAM_RIDDLER_WAS_HERE_0343` — lore string |
| Attacker accessed `/admin/renewal/delete` | Looks like the key action | Distraction — flag is in the headers, not the endpoints |

---

## 🛠️ Tools Players Might Use

```bash
# Filter by user
grep "dmitchell" access.log

# Filter by IP change
grep "dmitchell" access.log | awk '{print $1}' | sort | uniq -c

# Extract last field (token column)
grep "185.220.101.47" access.log | awk -F'"' '{print $NF}'

# One-liner decode
grep "185.220.101.47.*dmitchell" access.log \
  | grep -oP '"[A-Za-z0-9+/=]+"$' \
  | tr -d '"' \
  | while read t; do echo "$t" | base64 -d; done
```

---

## 💡 Hint (optional, costs points)
> *"He wore Mitchell's face.*
> *But his hands moved differently.*
> *And he whispered something in every step.*
> *Six whispers. Same voice. One message."*
> — UA + IP both change at the same second. That second is the answer.

---

## 📚 What This Teaches
- Apache log format parsing
- Session hijacking detection (IP + UA correlation)
- Distinguishing legitimate IP changes (VPN) from malicious ones
- Custom HTTP header forensics
- Multi-part Base64 reconstruction
- The difference between behavioral anomaly and confirmed attack
