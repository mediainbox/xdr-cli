# 🎛️ XDR Control CLI (`xdrctl.py`)

Command-line interface for communicating with the [`xdrd`](https://github.com/kkonradpl/xdrd) daemon, which controls FM/DAB receivers via ASCII commands over TCP.

It supports authentication, tuning, audio and RF control, reading current status, and real-time monitoring (RDS, signal level, etc.) with **human-readable or JSON output**.

---

## 📦 Installation

```bash
sudo apt install python3-click
chmod +x xdrctl.py
```

(You can also place it in `/usr/local/bin/xdrctl` for global access.)

---

## 🔐 Authentication

`xdrd` uses a **challenge-response (salt)** authentication mechanism:

1. The server sends a random salt line on connection.  
2. The client responds with `SHA1(salt + password)` as a 40-character hex string followed by `\n`.  
3. If it matches, access is granted (`a0` = wrong password, `a1` = guest access).

The CLI handles this automatically.

---

## ⚙️ Basic usage

```bash
export XDRD_PASS='123qwe'

./xdrctl.py --host 192.168.86.42 --port 7370 status
```

Readable output:
```
mode     : 0
volume   : 78
freq_khz : 99900
freq_mhz : 99.9
deemphasis : 0
```

JSON output:
```bash
./xdrctl.py --host 192.168.86.42 --port 7370 status --json
```

```json
{
  "mode": 0,
  "volume": 78,
  "freq_khz": 99900,
  "freq_mhz": 99.9,
  "deemphasis": 0
}
```

---

## 🔧 Global parameters

| Flag | Description |
|------|--------------|
| `--host` | IP or hostname of the `xdrd` daemon |
| `--port` | TCP port (default: 7373) |
| `--password` | Direct password input |
| `--password-file` | Path to file containing the password |
| `--read-seconds` | How long to keep reading after sending a command |
| `--json` | Structured JSON output (1 object per event) |

The environment variable `XDRD_PASS` is also supported.

---

## 🕒 About `--read-seconds`

Specifies **how long the CLI should listen for replies after sending a command**.

| Use case | Suggested value |
|-----------|----------------|
| Immediate response only | `--read-seconds 0.3` |
| Wait for confirmation + state | `--read-seconds 1.0` |
| Capture RDS / signal updates | `--read-seconds 2–3` |

Example:
```bash
xdrctl.py tune 101700 --read-seconds 3 --json
```

This reads all daemon messages (`T`, `P`, `R`, `Ss`, etc.) for the next 3 seconds.

---

## 🧩 Available commands

| Command | Description | Example |
|----------|--------------|----------|
| `status` | Show current tuner status | `xdrctl.py status` |
| `listen` | Monitor live events | `xdrctl.py listen --json` |
| `tune <kHz>` | Tune frequency in kHz | `xdrctl.py tune 101700` |
| `volume <n>` | Set volume (0–100) | `xdrctl.py volume 80` |
| `bandwidth <n>` | Set IF bandwidth | `xdrctl.py bandwidth 2` |
| `filter <n>` | Select IF filter | `xdrctl.py filter 1` |
| `mode <n>` | Set tuner mode (mono/stereo) | `xdrctl.py mode 0` |
| `deemp <n>` | De-emphasis (0=50µs, 1=75µs) | `xdrctl.py deemp 1` |
| `agc <n>` | Automatic gain control | `xdrctl.py agc 0` |
| `antenna <n>` | Select antenna | `xdrctl.py antenna 1` |
| `gain <n>` | Manual gain adjustment | `xdrctl.py gain 15` |
| `daa <n>` | DAA adjustment | `xdrctl.py daa 1` |
| `squelch <n>` | Noise threshold | `xdrctl.py squelch 0` |
| `rotator <n>` | Control antenna rotator | `xdrctl.py rotator 0` |
| `interval --sampling N --detector M` | Configure interval/detector | `xdrctl.py interval --sampling 0 --detector 1` |
| `raw "text"` | Send custom line (advanced) | `xdrctl.py raw "T101700\n"` |

---

## 📡 `listen`: live monitoring

Continuously listens for all events from the daemon: frequency changes, signal strength, RDS data, connected users, etc.

```bash
xdrctl.py listen
```

Text example:
```
signal: level=85.1 quality=9 extra=-1
RDS PI: 6A3D
RDS: 99.9 LA (hex:200039392E3900)
```

JSON example:
```bash
xdrctl.py listen --json
```

```json
{"type":"signal","level":85.1,"quality":9,"extra":-1}
{"type":"pi","pi_hex":"6A3D","pi_int":27197}
{"type":"rds","hex":"200039392E3900","text":"99.9"}
```

---

## 🧠 Decoded events

| Prefix | Meaning | Example | Output |
|---------|----------|----------|---------|
| `M` | Mode | `M0` | `mode=0` |
| `T` | Frequency (kHz) | `T99900` | `freq_mhz=99.9` |
| `Y` | Volume | `Y78` | `volume=78` |
| `P` | RDS PI code | `P6A3D` | `pi=0x6A3D` |
| `R` | RDS text (hex) | `R200039392E3900` | `"99.9"` |
| `Ss` | Signal | `Ss85.1,11,-1` | level=85.1, quality=11 |
| `o` | Connections | `o2,0` | 2 authorized, 0 guests |

---

## 🧰 Useful examples

### Change frequency and read full state
```bash
xdrctl.py tune 99900 --read-seconds 2 --json
```

### Increase volume and confirm
```bash
xdrctl.py volume 90 --read-seconds 0.5
```

### Listen to RDS and signal for 10 seconds
```bash
xdrctl.py listen --json | jq
```

### Get current frequency from a shell script
```bash
FREQ=$(xdrctl.py status --json | jq '.freq_mhz')
echo "Current frequency: $FREQ MHz"
```

---

## 🧾 License

MIT © Mediainbox, 2025  
Based on `xdr-protocol.h` from [kkonradpl/xdrd](https://github.com/kkonradpl/xdrd).
