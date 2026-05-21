# wifi-scanner

A Python tool that reads publicly broadcast 802.11 beacon frames on macOS and displays nearby WiFi networks in a colour-coded terminal table — sorted by signal strength with per-network security risk assessment.

> **Legal note:** SSIDs, BSSIDs, RSSI, and channel numbers are continuously broadcast by every access point as public 802.11 beacon frames. Reading them requires no association, no credentials, and no decryption — it is the same data shown in macOS's own WiFi menu.

---

## How it works

1. **Data source** — Calls the macOS `airport` utility, which performs a passive scan and returns one row per access point that sent a beacon frame.

2. **Parsing** — Locates the BSSID field (`XX:XX:XX:XX:XX:XX`) as an anchor, then extracts SSID, RSSI, channel, and security flags from surrounding columns.

3. **Sorting** — Networks are sorted by RSSI (strongest first) so the most relevant results appear at the top.

4. **Risk assessment** — The security column is colour-coded:

   | Protocol | Colour    | Why                                        |
   |----------|-----------|--------------------------------------------|
   | WPA3     | Green     | SAE handshake; resists offline cracking    |
   | WPA2     | Yellow    | Secure with strong passphrase              |
   | WPA      | Red       | TKIP deprecated; practical attacks exist   |
   | WEP      | Red       | RC4 stream cipher broken; trivial to crack |
   | Open     | Red       | No encryption; traffic is plaintext        |

5. **Display** — Uses the [`rich`](https://github.com/Textualize/rich) library for a colour-coded terminal table with optional auto-refresh (live dashboard mode).

---

## Requirements

- macOS (uses the built-in `airport` utility)
- Python 3.9+
- `rich` library

---

## Installation

```bash
git clone https://github.com/RocmDaGr8/wifi-scanner.git
cd wifi-scanner
pip3 install -r requirements.txt
```

---

## Usage

```bash
# One-shot scan (default)
python3 scanner.py

# Auto-refresh every 10 seconds (live dashboard)
python3 scanner.py -w 10

# Show only the top 15 strongest networks
python3 scanner.py -n 15

# Top 10, refresh every 5 seconds, skip legend
python3 scanner.py -n 10 -w 5 --no-legend
```

### Options

| Flag            | Description                                        |
|-----------------|----------------------------------------------------|
| `-w, --watch N` | Auto-refresh every N seconds (0 = one shot)        |
| `-n, --limit N` | Show only the top N networks by signal strength    |
| `--no-legend`   | Skip the security protocol colour legend           |

---

## Signal strength guide

| dBm range  | Rating    | Typical distance   |
|------------|-----------|--------------------|
| >= -50     | Excellent | ~1-2 m             |
| -50 to -60 | Good      | ~5-10 m            |
| -60 to -70 | Fair      | Usable             |
| -70 to -80 | Weak      | Marginal           |
| < -80      | Poor      | Barely detectable  |

---

## Project context

Built as part of a cybersecurity portfolio — 12-week roadmap targeting SOC / junior security analyst roles.

**Related projects:**
- [`dns-exfil-detector`](https://github.com/RocmDaGr8/dns-exfil-detector) — Detect DNS-based data exfiltration via entropy analysis
- [`network-traffic-analyzer`](https://github.com/RocmDaGr8/network-traffic-analyzer) — Port scan and traffic anomaly detection
- [`secure-data-storage`](https://github.com/RocmDaGr8/secure-data-storage) — AES-256-CBC file encryption with PBKDF2 key derivation

---

## Author

**Roshim Bhatta** — Rowan University, B.S. Computer Science  
GitHub: [@RocmDaGr8](https://github.com/RocmDaGr8)
