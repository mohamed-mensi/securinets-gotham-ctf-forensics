# Challenge 9 — "Slow Exfil"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"He didn't send a file.*
> *He didn't write a message.*
> *He asked questions — sixty of them —*
> *one every six minutes, for four hours.*
> *And in the asking, everything was said."*
>
> Gotham PD captured traffic from Mitchell's workstation
> the night of the gala. Sixty outbound HTTPS connections.
> Nothing in the payloads — they're encrypted.
> But the destination names were chosen very carefully.
>
> Read between the handshakes.

**File:** `slow_exfil.pcap`
**Category:** Forensics — Network
**Difficulty:** Hard
**Points:** 500

---

## 🎯 Intended Solve Path

### Step 1 — Open in Wireshark, survey the traffic

60 TLS Client Hello packets, all port 443, all from `192.168.1.45`.
Two destination IPs appear:
- `185.220.101.47` — appears 40 times
- Various legitimate-looking IPs (`142.250.x.x`, `13.32.x.x`, etc.) — appear 20 times total

The SNI field (Server Name Indication) in each TLS Client Hello shows the intended hostname.

### Step 2 — Extract all SNI values

**Wireshark filter:**
```
tls.handshake.extensions_server_name
```

**tshark command:**
```bash
tshark -r slow_exfil.pcap \
  -Y "tls.handshake.type == 1" \
  -T fields \
  -e frame.time_epoch \
  -e ip.dst \
  -e tls.handshake.extensions_server_name
```

Output (mixed):
```
1667505609  185.220.101.47   cw.t00.cdn-update.net
1667505609  13.32.99.103     dXBkYXRl.cdn-static.net
1667505970  185.220.101.47   ZQ.t01.cdn-update.net
1667506350  185.220.101.47   Yw.t02.cdn-update.net
...
```

### Step 3 — Identify signal vs noise

Two domain families:
- `*.cdn-update.net` — always destined to `185.220.101.47`
- `*.cdn-static.net` — destined to legitimate CDN IPs

The `cdn-update.net` subdomains contain the encoded data.
The `cdn-static.net` subdomains are noise — they decode to plain English words.

### Step 4 — Extract and sort the signal packets

```python
import subprocess, base64, re

result = subprocess.run([
    'tshark', '-r', 'slow_exfil.pcap',
    '-Y', 'tls.handshake.type == 1',
    '-T', 'fields',
    '-e', 'frame.time_epoch',
    '-e', 'ip.dst',
    '-e', 'tls.handshake.extensions_server_name'
], capture_output=True, text=True)

packets = []
for line in result.stdout.strip().splitlines():
    ts, dst, sni = line.split('\t')
    if dst == '185.220.101.47':
        packets.append((float(ts), sni))

packets.sort(key=lambda x: x[0])
```

### Step 5 — Decode each SNI in timestamp order

Each SNI has the form: `<b64chunk>.t<seq>.cdn-update.net`
The `t<seq>` field also encodes the sequence number as a redundant check.

```python
def pad(s): return s + '=' * (-len(s) % 4)

flag = ""
for ts, sni in packets:
    subdomain = sni.split('.')[0]
    chunk = base64.b64decode(pad(subdomain)).decode()
    flag += chunk

print(flag)
# → securinets_isgt{sn1_3xf1l_sl0w_and_st34lthy}
```

### Step 6 — Alternatively: one-liner with tshark + Python

```bash
tshark -r slow_exfil.pcap \
  -Y "tls.handshake.type == 1 && ip.dst == 185.220.101.47" \
  -T fields -e frame.time_epoch \
  -e tls.handshake.extensions_server_name \
  | sort -n \
  | awk '{print $2}' \
  | cut -d. -f1 \
  | python3 -c "
import sys, base64
flag = ''
for s in sys.stdin.read().split():
    s += '=' * (-len(s) % 4)
    flag += base64.b64decode(s).decode()
print(flag)
"
```

---

## 🚩 Flag
```
securinets_isgt{sn1_3xf1l_sl0w_and_st34lthy}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `*.cdn-static.net` SNIs | Look Base64-encoded — must be signal | Decode to plain English words: "update", "telemetry", etc. |
| Multiple destination IPs | All could be C2 | Only `185.220.101.47` carries the covert channel |
| `.t00` to `.t39` sequence numbers | Could be decoded separately | Just ordering helpers — the b64 subdomain carries the actual data |
| Packets mixed with noise in timeline | Ordering seems impossible | Filter by dst IP first, then sort by timestamp |

---

## 🛠️ Tools

```bash
# Wireshark display filter for SNI
tls.handshake.extensions_server_name

# tshark field extraction
tshark -r slow_exfil.pcap -Y "tls.handshake.type == 1" \
  -T fields -e frame.time_epoch -e ip.dst \
  -e tls.handshake.extensions_server_name

# Python solve script (see slow_exfil_solver_SOLUTION.py)
python3 slow_exfil_solver_SOLUTION.py slow_exfil.pcap
```

---

## 💡 Hint (optional, costs points)
> *"Not all questions are equal.*
> *Some go to strangers. Some go to the same address.*
> *Count the destinations.*
> *Then read what was asked — in the order it was asked."*
> — Filter by destination IP. Sort by time. Decode the subdomain.

---

## 📚 What This Teaches
- TLS SNI field forensics
- Covert channel detection in protocol metadata
- Distinguishing signal from noise in network captures
- tshark field extraction and scripted analysis
- Why encrypted traffic still leaks information through metadata
- Timestamp-based ordering as part of the encoding scheme
