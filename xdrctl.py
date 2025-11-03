#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import hashlib
import json
import re
import string
import click

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7373  # default xdrd TCP port

# -----------------------------
# Networking & AUTH utilities
# -----------------------------
def recv_line(sock, timeout=2.0, maxlen=4096):
    """Read a single line (ending with '\n') with a timeout."""
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < maxlen:
            ch = sock.recv(1)
            if not ch:
                break
            buf += ch
            if ch == b"\n":
                break
    except socket.timeout:
        pass
    return buf

def connect_and_auth(host, port, password, timeout=3.0):
    """
    xdrd AUTH flow:
      1) connect
      2) read SALT line from server
      3) send SHA1(SALT + password) in hex + '\n'
      4) 'a0\n' => unauthorized; 'a1\n' => guest; otherwise OK
    """
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)

    # 1) Read SALT
    salt_line = recv_line(s, timeout=timeout).rstrip(b"\r\n")
    if not salt_line:
        s.close()
        raise click.ClickException("Did not receive SALT from server (timeout).")

    # 2) Compute SHA1(SALT + password) -> lowercase hex (40 chars)
    if password is None:
        s.close()
        raise click.ClickException("Missing password (use --password, --password-file or XDRD_PASS).")
    sha = hashlib.sha1()
    sha.update(salt_line)
    sha.update(password.encode("utf-8"))
    digest_hex = sha.hexdigest()

    # 3) Send hex + '\n'
    s.sendall(digest_hex.encode("ascii") + b"\n")

    # 4) Optionally read a short reply ('a0\n' or 'a1\n')
    resp = recv_line(s, timeout=1.0)
    if resp == b"a0\n":
        s.close()
        raise click.ClickException("Auth rejected: a0 (wrong password).")
    # 'a1\n' = guest (read-only). If nothing comes, consider OK.

    return s, resp.decode(errors="replace").strip() if resp else ""

def send_line(sock, line: str, timeout=2.0):
    """Send a raw ASCII line (no automatic newline unless included)."""
    sock.settimeout(timeout)
    sock.sendall(line.encode("ascii"))

def drain_read(sock, timeout=0.5, limit=65536):
    """
    Quickly read whatever is available within 'timeout' and return bytes.
    Useful after AUTH or after sending a command to receive events/echo.
    """
    sock.settimeout(timeout)
    buf = b""
    try:
        while len(buf) < limit:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(chunk) < 4096:
                break
    except socket.timeout:
        pass
    return buf

def print_lines(prefix: str, b: bytes):
    """Print decoded lines with optional prefix."""
    if not b:
        return
    for line in b.splitlines():
        try:
            print(f"{prefix}{line.decode('utf-8', errors='replace')}")
        except Exception:
            print(f"{prefix}{line!r}")

# -----------------------------
# STATUS / event parser
# -----------------------------
RE_INT = re.compile(r"^-?\d+$")

def parse_state_lines(lines):
    """
    Convert lines like:
      M0 / Y78 / T99900 / D0 / A0 / W0 / Z0 / G00 / V0 / Q0 / C0 / I0,0
    into a readable dict + useful conversions (T -> MHz, I -> split fields).
    """
    state = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue

        k = line[0:1]
        v = line[1:]

        if k == "I":
            parts = v.split(",", 1)
            if len(parts) == 2 and RE_INT.match(parts[0]) and RE_INT.match(parts[1]):
                state["interval_sampling"] = int(parts[0])
                state["interval_detector"] = int(parts[1])
            else:
                state["interval_raw"] = v
            continue

        if RE_INT.match(v):
            ival = int(v)
        else:
            ival = v

        if k == "M":
            state["mode"] = ival
        elif k == "Y":
            state["volume"] = ival
        elif k == "T":
            state["freq_khz"] = ival
            try:
                state["freq_mhz"] = round(ival / 1000.0, 3)
            except Exception:
                pass
        elif k == "D":
            state["deemphasis"] = ival
        elif k == "A":
            state["agc"] = ival
        elif k == "F":
            state["filter"] = ival
        elif k == "W":
            state["bandwidth"] = ival
        elif k == "Z":
            state["antenna"] = ival
        elif k == "G":
            state["gain"] = ival
        elif k == "V":
            state["daa"] = ival
        elif k == "Q":
            state["squelch"] = ival
        elif k == "C":
            state["rotator"] = ival
        else:
            state[f"unknown_{k}"] = v

    return state

def print_table(d):
    """Print a key/value table."""
    if not d:
        print("(no data)")
        return
    width = max(len(k) for k in d.keys())
    for k in sorted(d.keys()):
        print(f"{k.ljust(width)} : {d[k]}")

def _printable_ascii(bs: bytes) -> str:
    """Return a printable ASCII-only string from bytes (drop NUL and controls)."""
    s = "".join(chr(b) if chr(b) in string.printable and b not in (0x0b,0x0c) else "" for b in bs)
    return s.strip()

def parse_event_line(line: str):
    """
    Parse a single daemon event line into a dict.
    Types: state(M/Y/T/D/A/W/Z/G/V/Q/C/I), online(o), signal(Ss...), pi(P...), rds(R...),
           unknown(...)
    """
    line = line.strip()
    if not line:
        return None

    k = line[0]
    v = line[1:]

    # online: o<auth>,<guests>
    if k == "o":
        try:
            a, g = v.split(",", 1)
            return {"type": "online", "auth": int(a), "guests": int(g)}
        except Exception:
            return {"type": "online_raw", "raw": line}

    # PI: P<hex>
    if k == "P":
        return {"type": "pi", "pi_hex": v, "pi_int": int(v, 16) if all(c in string.hexdigits for c in v) else None}

    # RDS hex payload (attempt basic ASCII reconstruction)
    if k == "R":
        hexstr = v
        try:
            bs = bytes.fromhex(hexstr)
            ascii_guess = _printable_ascii(bs.replace(b"\x00", b""))
        except ValueError:
            bs, ascii_guess = b"", ""
        out = {"type": "rds", "hex": hexstr}
        if ascii_guess:
            out["text"] = ascii_guess
        return out

    # Signal line (e.g., "Ss85.01,11,-1")
    if line.startswith("Ss"):
        parts = line[2:].split(",")
        nums = []
        for p in parts:
            try:
                nums.append(float(p))
            except ValueError:
                nums.append(p)
        out = {"type": "signal", "raw": line}
        if len(nums) >= 1: out["level"] = nums[0]
        if len(nums) >= 2: out["quality"] = nums[1]
        if len(nums) >= 3: out["extra"] = nums[2]
        return out

    # Standard state lines (single-letter + value, or 'I<sampling>,<detector>')
    if k in ("M","Y","T","D","A","W","Z","G","V","Q","C"):
        try:
            ival = int(v)
        except ValueError:
            ival = v
        keymap = {
            "M":"mode","Y":"volume","T":"freq_khz","D":"deemphasis","A":"agc",
            "W":"bandwidth","Z":"antenna","G":"gain","V":"daa","Q":"squelch","C":"rotator"
        }
        out = {"type":"state", "key": keymap[k], "value": ival}
        if k == "T" and isinstance(ival, int):
            out["freq_mhz"] = round(ival/1000.0, 3)
        return out

    if k == "I":
        try:
            s,d = v.split(",",1)
            return {"type":"state","key":"interval","sampling":int(s), "detector":int(d)}
        except Exception:
            return {"type":"state_raw","raw": line}

    return {"type":"unknown", "raw": line}

def parse_lines_to_events(lines):
    """Parse multiple text lines into a list of event dicts."""
    evs = []
    for ln in lines:
        ev = parse_event_line(ln)
        if ev:
            evs.append(ev)
    return evs

# -----------------------------
# CLI
# -----------------------------
@click.group(help="xdrd CLI: AUTH via SHA1(salt+password) and ASCII commands (T/W/F/...).")
@click.option("--host", default=DEFAULT_HOST, show_default=True)
@click.option("--port", default=DEFAULT_PORT, type=int, show_default=True)
@click.option("--password", default=None, help="xdrd server password. You can also use XDRD_PASS or --password-file.")
@click.option("--password-file", type=click.Path(exists=True), default=None, help="Read password from file.")
@click.pass_context
def cli(ctx, host, port, password, password_file):
    # Resolve password: flag > file > env
    pwd = password
    if pwd is None and password_file:
        with open(password_file, "r", encoding="utf-8", errors="ignore") as f:
            pwd = f.read().strip()
    if pwd is None:
        pwd = os.environ.get("XDRD_PASS")

    ctx.ensure_object(dict)
    ctx.obj["host"] = host
    ctx.obj["port"] = port
    ctx.obj["password"] = pwd

# -----------------------------
# High-level commands
# -----------------------------
@cli.command(help="Show current state as a table or JSON (reads the initial dump after AUTH).")
@click.option("--read-seconds", default=1.0, show_default=True, type=float, help="How long to keep reading after AUTH.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def status(ctx, read_seconds, as_json):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    data = drain_read(s, timeout=read_seconds)
    s.close()
    lines = data.decode("utf-8", errors="replace").splitlines()
    state = parse_state_lines(lines)
    if as_json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
    else:
        print_table(state)

@cli.command(help="Listen indefinitely and decode events (Ctrl+C to exit).")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit one JSON object per event.")
@click.pass_context
def listen(ctx, as_json):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    if banner:
        ev = parse_event_line(banner)
        if as_json and ev:
            print(json.dumps(ev, ensure_ascii=False))
        else:
            print(f"(server) {banner}")

    print("(listening... Ctrl+C to exit)")
    try:
        while True:
            line_b = recv_line(s, timeout=60.0)
            if not line_b:
                continue
            line = line_b.decode("utf-8", errors="replace").rstrip("\r\n")
            ev = parse_event_line(line)

            if as_json:
                if ev:
                    print(json.dumps(ev, ensure_ascii=False))
            else:
                if ev and ev.get("type") == "state" and ev.get("key") == "interval":
                    print(f"I: sampling={ev['sampling']}, detector={ev['detector']}")
                elif ev and ev.get("type") == "state":
                    k = ev["key"]; val = ev["value"]
                    if k == "freq_khz" and "freq_mhz" in ev:
                        print(f"Tuned: {val} kHz ({ev['freq_mhz']} MHz)")
                    else:
                        print(f"{k}: {val}")
                elif ev and ev.get("type") == "online":
                    print(f"online: auth={ev['auth']} guests={ev['guests']}")
                elif ev and ev.get("type") == "signal":
                    lvl = ev.get("level"); q = ev.get("quality"); x = ev.get("extra")
                    print(f"signal: level={lvl} quality={q} extra={x}")
                elif ev and ev.get("type") == "pi":
                    print(f"RDS PI: {ev['pi_hex']}")
                elif ev and ev.get("type") == "rds":
                    txt = ev.get("text")
                    if txt:
                        print(f"RDS: {txt}    (hex:{ev['hex']})")
                    else:
                        print(f"RDS hex: {ev['hex']}")
                else:
                    print(line)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

@cli.command(help="Send a raw line (nothing added). Useful for tests, e.g. 'T101700\\n'.")
@click.argument("text", nargs=-1, required=True)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def raw(ctx, text, read_seconds, as_json):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    payload = " ".join(text)
    send_line(s, payload)
    data = drain_read(s, timeout=read_seconds)
    s.close()
    lines = data.decode("utf-8", errors="replace").splitlines()
    if as_json:
        evs = parse_lines_to_events(lines)
        for ev in evs:
            print(json.dumps(ev, ensure_ascii=False))
    else:
        print_lines("", data)

# -----------------------------
# ASCII command wrappers
# -----------------------------
def _send_and_print(ctx, line_to_send, read_seconds, as_json, read_back=True):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    send_line(s, line_to_send + "\n")
    data = drain_read(s, timeout=read_seconds) if read_back else b""
    s.close()

    if as_json:
        lines = data.decode("utf-8", errors="replace").splitlines()
        evs = parse_lines_to_events(lines)
        for ev in evs:
            print(json.dumps(ev, ensure_ascii=False))
    else:
        print_lines("", data)

@cli.command(help="Tune in kHz. Example: 101700 means 101.7 MHz.")
@click.argument("khz", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def tune(ctx, khz, read_seconds, as_json):
    _send_and_print(ctx, f"T{khz}", read_seconds, as_json)

@cli.command(help="IF bandwidth (W). Integer: 0..N (firmware dependent).")
@click.argument("code", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def bandwidth(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"W{code}", read_seconds, as_json)

@cli.command(help="IF filter (F). Integer (or -1 for daemon default).")
@click.argument("code", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def filter(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"F{code}", read_seconds, as_json)

@cli.command(help="Mode (M). Integer (firmware dependent).")
@click.argument("mode", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def mode(ctx, mode, read_seconds, as_json):
    _send_and_print(ctx, f"M{mode}", read_seconds, as_json)

@cli.command(help="Volume (Y). Typically 0..100.")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def volume(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Y{value}", read_seconds, as_json)

@cli.command(help="De-emphasis (D). 0/1 (firmware mapping e.g. 0=50us, 1=75us).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def deemp(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"D{value}", read_seconds, as_json)

@cli.command(help="AGC (A). Integer (firmware dependent).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def agc(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"A{value}", read_seconds, as_json)

@cli.command(help="Antenna (Z). Integer (firmware dependent).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def antenna(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Z{value}", read_seconds, as_json)

@cli.command(help="Gain (G). Integer (daemon prints with %02d).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def gain(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"G{value:02d}", read_seconds, as_json)

@cli.command(help="DAA (V). Integer (firmware dependent).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def daa(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"V{value}", read_seconds, as_json)

@cli.command(help="Squelch (Q). Integer (firmware dependent).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def squelch(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Q{value}", read_seconds, as_json)

@cli.command(help="Rotator (C). Integer (firmware dependent).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def rotator(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"C{value}", read_seconds, as_json)

@cli.command(help="Interval/Detector (I). Example: --sampling 0 --detector 1 -> 'I0,1'.")
@click.option("--sampling", required=True, type=int)
@click.option("--detector", required=True, type=int, help="0/1")
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def interval(ctx, sampling, detector, read_seconds, as_json):
    _send_and_print(ctx, f"I{sampling},{detector}", read_seconds, as_json)

# -----------------------------
# Startup / Shutdown
# -----------------------------
@cli.command(name="init", help="Initializer/startup command (sends 'x').")
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def init_cmd(ctx, read_seconds, as_json):
    # 'x' = XDR_P_STARTUP
    _send_and_print(ctx, "x", read_seconds, as_json)

@cli.command(help="Shutdown/power-off command (sends 'X').")
@click.option("--read-seconds", default=0.6, show_default=True, type=float, help="How long to read after sending.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output.")
@click.pass_context
def shutdown(ctx, read_seconds, as_json):
    # 'X' = XDR_P_SHUTDOWN
    _send_and_print(ctx, "X", read_seconds, as_json)

# -----------------------------
# Full initialization sequence
# -----------------------------
@cli.command(name="init-full", help="Run full initialization: x + defaults (override via flags), optional tune and status.")
@click.option("--mode", default=0, show_default=True, type=int, help="M (mode), default 0=FM.")
@click.option("--volume", default=100, show_default=True, type=int, help="Y (volume) 0..100.")
@click.option("--deemp", default=0, show_default=True, type=int, help="D (de-emphasis) e.g., 0=50us, 1=75us.")
@click.option("--agc", default=2, show_default=True, type=int, help="A (AGC mode).")
@click.option("--filter", "if_filter", default=-1, show_default=True, type=int, help="F (IF filter), -1=auto.")
@click.option("--bandwidth", default=0, show_default=True, type=int, help="W (IF bandwidth).")
@click.option("--antenna", default=0, show_default=True, type=int, help="Z (antenna index).")
@click.option("--gain", default=0, show_default=True, type=int, help="G (gain).")
@click.option("--daa", default=0, show_default=True, type=int, help="V (DAA).")
@click.option("--squelch", default=0, show_default=True, type=int, help="Q (squelch).")
@click.option("--rotator", default=0, show_default=True, type=int, help="C (rotator).")
@click.option("--sampling", default=0, show_default=True, type=int, help="I sampling.")
@click.option("--detector", default=0, show_default=True, type=int, help="I detector (0/1).")
@click.option("--freq-khz", type=int, default=None, help="Optional T (tune) in kHz.")
@click.option("--status", is_flag=True, default=False, help="Append 'S' at the end to dump state.")
@click.option("--read-seconds", default=2.0, show_default=True, type=float, help="Total read window after sending the sequence.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON output (one object per event).")
@click.pass_context
def init_full(ctx, mode, volume, deemp, agc, if_filter, bandwidth, antenna, gain, daa, squelch, rotator,
              sampling, detector, freq_khz, status, read_seconds, as_json):
    """
    Sends: x, M, Y, D, A, F, W, Z, G, V, Q, C, I[, T][, S]
    in a single authenticated connection, then reads for --read-seconds.
    """
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])

    cmds = [
        "x",
        f"M{mode}",
        f"Y{volume}",
        f"D{deemp}",
        f"A{agc}",
        f"F{if_filter}",
        f"W{bandwidth}",
        f"Z{antenna}",
        f"G{gain:02d}",
        f"V{daa}",
        f"Q{squelch}",
        f"C{rotator}",
        f"I{sampling},{detector}",
    ]
    if freq_khz is not None:
        cmds.append(f"T{freq_khz}")
    if status:
        cmds.append("S")

    payload = "\n".join(cmds) + "\n"
    send_line(s, payload)

    data = drain_read(s, timeout=read_seconds)
    s.close()

    if as_json:
        lines = data.decode("utf-8", errors="replace").splitlines()
        evs = parse_lines_to_events(lines)
        for ev in evs:
            print(json.dumps(ev, ensure_ascii=False))
    else:
        print_lines("", data)

if __name__ == "__main__":
    cli()
