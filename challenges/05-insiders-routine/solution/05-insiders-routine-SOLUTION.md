# Challenge 6 — "The Insider's Routine"
## Theme: The Riddler / The Batman (2022)

---

## 📋 Challenge Description (shown to players)

> *"One of them was always there.*
> *Not when the others were watching.*
> *Every night. Same time. Same door.*
> *Routine is the enemy of secrecy —*
> *and the friend of those who know how to read it."*
>
> Gotham City server. Five authorized users.
> One of them has been leaking the Renewal files for two weeks.
> No malware. No exploits. Just legitimate commands.
> The pattern is there. Find it.

**Files:**
- `auth.log` — SSH authentication log, 14 days
- `cron.log` — Cron daemon log, 14 days
- `bash_histories/.bash_history_jgordon`
- `bash_histories/.bash_history_bwayne`
- `bash_histories/.bash_history_hdent`
- `bash_histories/.bash_history_lkane`
- `bash_histories/.bash_history_enashton`

**Category:** Forensics
**Difficulty:** Medium/Hard
**Points:** 450

---

## 🎯 Intended Solve Path

### Step 1 — Profile login patterns from auth.log

```bash
grep "Accepted" auth.log | awk '{print $9, $11}' | sort
```

| User | Login pattern |
|------|--------------|
| jgordon | 08:00–09:00, weekdays only |
| bwayne | Irregular hours, 9AM–10PM |
| hdent | 09:00–17:00, two late nights (23:00 on days 3 and 9) |
| lkane | Sparse, 10:00–11:00 on 6 days |
| **enashton** | **03:00 AM, every single night, 14/14 days** |

`enashton` is the only user with a perfectly consistent 3AM login pattern across all 14 days. This is the behavioral anomaly.

### Step 2 — Corroborate with cron.log

```bash
grep "enashton" cron.log
```

Two cron entries fire every night:
- `03:01:00` — `/usr/local/bin/system-cleanup` (disguised as legit)
- `03:05:00` — `/tmp/.maintenance.sh` (hidden script in /tmp — highly suspicious)

The `.maintenance.sh` path in `/tmp` is a strong indicator of persistence.
Compare: no other user has cron entries except `jgordon` (weekly report, daytime).

### Step 3 — Inspect enashton's bash history

Cross-reference the commands against the timeline. 
Separate normal-looking commands from suspicious ones:

**Normal (ignore):**
```
ls -la /home/
cat /etc/motd
ls /var/log/
cat /proc/version
uptime
ps aux
date
ls /tmp/
history -c
ls -la /tmp/.bak/
echo "check complete"
cat /tmp/.y
rm /tmp/.cache_dump
exit
```

**Suspicious (flag commands) — in order:**
```
1.  inotifywait -m /etc/passwd -e access -e modify
2.  nmap -sn 10.0.0.0/24
3.  ss -tlnp | tee /tmp/.cache_dump
4.  id
5.  du -sh /home/* | sort -rh
6.  env | grep -i pass
7.  rsync -avz /etc/ /tmp/.bak/
8.  kill -0 $(cat /var/run/syslog.pid)
9.  netstat -an | grep ESTABLISHED
10. openssl enc -d -aes-256-cbc -in /tmp/.x -out /tmp/.y -k r3n3wal
11. who -a | tee /tmp/.who_log
12. stat /var/log/auth.log
```

### Step 4 — Extract first letters

```
inotifywait  → i
nmap         → n
ss           → s
id           → i
du           → d
env          → e
rsync        → r
kill         → k
netstat      → n
openssl      → o
who          → w
stat         → s
```

First letters: **i n s i d e r k n o w s**

**Flag:** `securinets_isgt{insiderknows}`

---

## 🚩 Flag
```
securinets_isgt{insiderknows}
```

---

## 🔴 Red Herrings Explained

| Element | What it looks like | What it actually is |
|---|---|---|
| `hdent` 23:00 logins (days 3 & 9) | Suspicious late access | Only twice in 14 days — not a pattern |
| `bwayne` runs `find / -name "*.key"` | Searching for keys? | In context of dev work — looking for his own SSH keys |
| `enashton` cron: `system-cleanup` | Legitimate system task | Cover name — the real payload is `.maintenance.sh` |
| `openssl` command with `-k r3n3wal` | The passphrase looks like the flag | It's a Riddler lore reference — not the flag |
| `history -c` in enashton's history | He cleared history (self-defeating) | The history was recovered from disk image anyway |

---

## 🛠️ Tools Players Might Use

```bash
# Find login hours per user
grep "Accepted" auth.log | awk '{print $9, substr($11,1,2)}' | sort | uniq -c

# Check enashton login consistency
grep "enashton" auth.log | grep "Accepted" | awk '{print $1,$2,$3}' 

# Find cron jobs by user
grep -v "root\|jgordon" cron.log | grep CMD

# View bash history
cat bash_histories/.bash_history_enashton

# First letters of suspicious commands (manual step)
# Players must identify which commands are suspicious vs normal
```

---

## 💡 Hint (optional, costs points)
> *"What does a ghost do every night at the same hour?*
> *And when you find the ghost — read what its hands spelled.*
> *Not the words. The initials."*
> — 3AM. 14 nights. First letter of each unusual command.

---

## 📚 What This Teaches
- Behavioral log analysis (pattern recognition over time)
- Distinguishing anomalous from suspicious (hdent's late logins vs enashton's pattern)
- Cron log forensics — spotting persistence mechanisms
- Bash history analysis and command intent classification
- The concept that malicious actors use legitimate tools (LOL bins)
- Multi-source correlation: auth + cron + shell history together tell a story
