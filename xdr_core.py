#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import hashlib
import json
import re
import string
import click

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7373  # xdrd default

# -----------------------------
# Networking & AUTH
# -----------------------------
def recv_line(sock, timeout=2.0, maxlen=4096):
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
    Flow:
      1) connect
      2) read SALT line
      3) send SHA1(salt + password) hex + '\n'
      4) read short reply (may be 'a0\\n' unauthorized or 'a1\\n' guest-ready)
    """
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)

    salt_line = recv_line(s, timeout=timeout).rstrip(b"\r\n")
    if not salt_line:
        s.close()
        raise click.ClickException("No SALT from server (timeout).")

    if password is None:
        s.close()
        raise click.ClickException("Missing password (use --password/--password-file or XDRD_PASS).")

    sha = hashlib.sha1()
    sha.update(salt_line)
    sha.update(password.encode("utf-8"))
    digest_hex = sha.hexdigest()

    s.sendall(digest_hex.encode("ascii") + b"\n")

    resp = recv_line(s, timeout=1.0)
    if resp == b"a0\n":
        s.close()
        raise click.ClickException("Auth rejected: a0 (wrong password).")
    # 'a1\\n' => guest-ready; empty => OK too
    return s, resp.decode(errors="replace").strip() if resp else ""

def send_line(sock, line: str, timeout=2.0):
    sock.settimeout(timeout)
    sock.sendall(line.encode("ascii"))

def drain_read(sock, timeout=0.5, limit=1 << 20):
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
    if not b:
        return
    for line in b.splitlines():
        try:
            print(f"{prefix}{line.decode('utf-8', errors='replace')}")
        except Exception:
            print(f"{prefix}{line!r}")

# -----------------------------
# Parsing helpers
# -----------------------------
RE_INT = re.compile(r"^-?\d+$")

def _printable_ascii(bs: bytes) -> str:
    return "".join(
        chr(b) if chr(b) in string.printable and b not in (0x0b, 0x0c) else ""
        for b in bs
    ).strip()

def parse_event_line(line: str):
    """
    Maps daemon lines to structured events, based on tuner.c:
      OK/X, M/Y/T/D/A/F/W/Z/G/V/Q/C/I, Ss/s/M..., P(hex with '?'), R(14|18 hex),
      U (scan), N (pilot), ! (external), o<auth,guests>, a<code>
    """
    line = line.strip()
    if not line:
        return None

    # Exact "OK" (tuner startup ack)
    if line == "OK":
        return {"type": "ready"}

    # Single-char shutdown marker (daemon stops thread)
    if line == "X":
        return {"type": "shutdown"}

    k = line[0]
    v = line[1:]

    if k == "o":
        # online users: "o<auth>,<guests>"
        try:
            a, g = v.split(",", 1)
            return {"type": "online", "auth": int(a), "guests": int(g)}
        except Exception:
            return {"type": "online_raw", "raw": line}

    if k == "a":
        # authorization: a0=unauthorized (disconnect), a1=guest-ready
        try:
            code = int(v)
        except Exception:
            return {"type": "auth_raw", "raw": line}
        if code == 0:
            return {"type": "auth", "authorized": False}
        if code == 1:
            return {"type": "auth", "authorized": True, "guest": True, "ready": True}
        return {"type": "auth", "code": code}

    if k == "!":
        return {"type": "external_event"}

    if k == "P":
        # PI: hex + optional '?' markers contributing to error bits
        pi_hex = v
        pi_int = None
        if all(c in string.hexdigits + "?" for c in pi_hex[:4]):
            try:
                base = int(pi_hex[:4], 16)
                err = pi_hex[4:].count("?")
                err = 3 if err > 3 else err
                pi_int = base | (err << 16)
            except Exception:
                pass
        return {"type": "pi", "pi_hex": pi_hex, "pi_int": pi_int}

    if k == "R":
        # RDS: legacy 14 hex or new 18 hex (we keep hex and try ASCII)
        hexstr = v
        out = {"type": "rds", "hex": hexstr, "len": len(hexstr)}
        try:
            bs = bytes.fromhex(hexstr)
            txt = _printable_ascii(bs.replace(b"\x00", b""))
            if txt:
                out["text"] = txt
        except ValueError:
            pass
        return out

    if k == "S":
        # Signal line. First char after 'S' encodes stereo flags:
        #   's' => stereo, 'S' => stereo+forced mono, 'M' => forced mono, else mono
        # Then numeric level; optionally ",cci,aci"
        if not v:
            return {"type": "signal_raw", "raw": line}
        flag = v[0]
        rest = v[1:]
        stereo = {
            "s": "stereo",
            "S": "stereo_forced_mono",
            "M": "forced_mono",
        }.get(flag, "mono")
        # rest looks like "85.01,11,-1" or "85.1"
        fields = rest.split(",") if rest else []
        lvl = None
        cci = None
        aci = None
        try:
            if fields and fields[0] != "":
                lvl = float(fields[0])
        except ValueError:
            pass
        if len(fields) >= 2:
            try:
                cci = int(fields[1])
            except ValueError:
                pass
        if len(fields) >= 3:
            try:
                aci = int(fields[2])
            except ValueError:
                pass
        ev = {"type": "signal", "stereo": stereo}
        if lvl is not None: ev["level"] = lvl
        if cci is not None: ev["cci"] = cci
        if aci is not None: ev["aci"] = aci
        return ev

    if k == "U":
        # Spectral scan payload (opaque here)
        return {"type": "scan", "raw": v}

    if k == "N":
        # Pilot injection estimation (integer)
        try:
            return {"type": "pilot", "value": int(v)}
        except ValueError:
            return {"type": "pilot_raw", "raw": line}

    if k in ("M","Y","T","D","A","F","W","Z","G","V","Q","C"):
        try:
            ival = int(v)
        except ValueError:
            ival = v
        keymap = {
            "M":"mode","Y":"volume","T":"freq_khz","D":"deemphasis","A":"agc",
            "F":"filter","W":"bandwidth","Z":"antenna","G":"gain","V":"daa",
            "Q":"squelch","C":"rotator"
        }
        out = {"type":"state", "key": keymap[k], "value": ival}
        if k == "T" and isinstance(ival, int):
            out["freq_mhz"] = round(ival/1000.0, 3)
        return out

    if k == "I":
        # In tu daemon puede llegar como "123" (sampling) o "s,d" (sampling,detector)
        if "," in v:
            s, d = v.split(",", 1)
            try:
                return {"type": "state", "key": "interval", "sampling": int(s), "detector": int(d)}
            except ValueError:
                return {"type": "state_raw", "raw": line}
        else:
            try:
                return {"type": "state", "key": "interval_sampling", "value": int(v)}
            except ValueError:
                return {"type": "state_raw", "raw": line}

    return {"type": "unknown", "raw": line}

def parse_lines_to_events(lines):
    evs = []
    for ln in lines:
        ev = parse_event_line(ln)
        if ev:
            evs.append(ev)
    return evs

def parse_state_lines(lines):
    """Build a status dict from the usual state dump (M/Y/T/D/A/W/Z/G/V/Q/C/I...)."""
    state = {}
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        # direct OK
        if line == "OK":
            state["ready"] = True
            continue
        ev = parse_event_line(line)
        if not ev:
            continue
        if ev.get("type") == "state":
            key = ev.get("key")
            if key == "deemphasis":
                state["deemphasis"] = calculate_deemphasis(ev["value"])
            elif key == "bandwidth":
                state["bandwidth"] = calculate_bandwidth(ev["value"])
            elif key == "daa":
                state["daa"] = calculate_daa(ev["value"])
            elif key == "freq_khz":
                state["freq_khz"] = ev["value"]
                state["freq_mhz"] = ev.get("freq_mhz")
            elif key == "interval":
                state["interval_sampling"] = ev.get("sampling")
                state["interval_detector"] = ev.get("detector")
            elif key:
                state[key] = ev["value"]
        elif ev.get("type") == "online":
            state["online_auth"] = ev["auth"]
            state["online_guests"] = ev["guests"]
        elif ev.get("type") == "pi":
            state["pi_hex"] = ev.get("pi_hex")
            state["pi_int"] = ev.get("pi_int")
        elif ev.get("type") == "rds":
            state["rds_hex"] = ev.get("hex")
            if "text" in ev:
                state["rds_text"] = ev["text"]
        elif ev.get("type") == "signal":
            state["signal_stereo"] = ev.get("stereo")
            state["signal_level"] = ev.get("level")
            state["signal_cci"] = ev.get("cci")
            state["signal_aci"] = ev.get("aci")
        elif ev.get("type") == "ready":
            state["ready"] = True
    return state

def calculate_deemphasis(value):
    return_value = ''
    if value == 0:
        return_value = "50 µs"
    elif value == 1:
        return_value = "75 µs"
    else:
        return_value = value

    return return_value

# bandwidth_code | bandwidth_label |Aprox. bandwidth
# 0              | wide            |~180 kHz – 200 kHz
# 1              | medium          |~150 kHz
# 2              | narrow          |~110 kHz – 120 kHz
def calculate_bandwidth(value):
    return_value = ''
    if value == 0:
        return_value = "wide"
    elif value == 1:
        return_value = "medium"
    elif value == 2:
        return_value = "narrow"
    else:
        return_value = value

    return return_value

def calculate_daa(value):
    return_value = ''
    if value == 0:
        return_value = "normal"
    elif value == 1:
        return_value = "dead air"
    elif value == 2:
        return_value = "error or unsupported mode"
    else:
        return_value = value

    return return_value

def print_table(d):
    if not d:
        print("(no data)")
        return
    width = max(len(k) for k in d.keys())
    for k in sorted(d.keys()):
        print(f"{k.ljust(width)} : {d[k]}")


def xdr_status(ctx, read_seconds, as_json):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    data = drain_read(s, timeout=read_seconds)
    s.close()
    lines = data.decode("utf-8", errors="replace").splitlines()

    st = parse_state_lines(lines)
    return_value = ''
    if as_json:
        return_value = json.dumps(st, ensure_ascii=False, indent=2)
    else:
        return_value = st
        
    return return_value

def xdr_listen(ctx, as_json):
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
            b = recv_line(s, timeout=60.0)
            if not b:
                continue
            line = b.decode("utf-8", errors="replace").rstrip("\r\n")
            ev = parse_event_line(line)
            if as_json:
                if ev: print(json.dumps(ev, ensure_ascii=False))
            else:
                if not ev:
                    print(line)
                    continue
                t = ev.get("type")
                if t == "ready": print("OK (tuner ready)")
                elif t == "shutdown": print("X (shutdown)")
                elif t == "state":
                    k = ev["key"]; v = ev["value"]
                    if k == "freq_khz":
                        mhz = ev.get("freq_mhz")
                        print(f"Tuned: {v} kHz ({mhz} MHz)")
                    elif k == "interval":
                        print(f"I: sampling={ev.get('sampling')}, detector={ev.get('detector')}")
                    else:
                        print(f"{k}: {v}")
                elif t == "online":
                    print(f"online: auth={ev['auth']} guests={ev['guests']}")
                elif t == "signal":
                    lvl = ev.get("level"); cci = ev.get("cci"); aci = ev.get("aci"); st = ev.get("stereo")
                    extra = []
                    if cci is not None: extra.append(f"CCI={cci}")
                    if aci is not None: extra.append(f"ACI={aci}")
                    extras = (" " + " ".join(extra)) if extra else ""
                    print(f"signal: level={lvl} stereo={st}{extras}")
                elif t == "pi":
                    print(f"RDS PI: {ev['pi_hex']} ({ev.get('pi_int')})")
                elif t == "rds":
                    txt = ev.get("text")
                    if txt: print(f"RDS: {txt}    (hex:{ev['hex']})")
                    else:  print(f"RDS hex: {ev['hex']}")
                elif t == "pilot":
                    print(f"pilot: {ev['value']}")
                elif t == "scan":
                    print(f"scan: {ev['raw']}")
                elif t == "auth":
                    if ev.get("authorized") is False: print("unauthorized (disconnect)")
                    elif ev.get("ready"): print("guest authorized (ready)")
                    else: print(f"auth code: {ev.get('code')}")
                elif t == "external_event":
                    print("external event (!)")
                else:
                    print(line)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()


def xdr_raw(ctx, text, read_seconds, as_json):
    s, _ = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    payload = " ".join(text)
    send_line(s, payload)
    data = drain_read(s, timeout=read_seconds)
    s.close()
    lines = data.decode("utf-8", errors="replace").splitlines()
    result = []
    if as_json:
        for ev in parse_lines_to_events(lines):
            result.append(json.dumps(ev, ensure_ascii=False))
    else:
        result = lines

    return result


def xdr_scan(ctx, read_seconds, as_json):
    s, _ = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    send_line(s, "Sa86000\n")
    send_line(s, "Sb108000\n")
    send_line(s, "Sc50\n")
    send_line(s, "Sw56000\n")
    send_line(s, "S\n")

    while True:
        data = drain_read(s, timeout=read_seconds)
        lines = data.decode("utf-8", errors="replace").splitlines()
        if len(lines) > 0 and len(lines[0]) > 0 and lines[0][0] == 'U':
            result = []
            if as_json:
                for ev in parse_lines_to_events(lines):
                    result.append(json.dumps(ev, ensure_ascii=False))
            else:
                result = lines
            break
                
    s.close()
    return result

def xdr_state(ctx, read_seconds, as_json):
    s, banner = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    recieved_state_info = False
    while True:
        send_line(s, "s\n")
        data = drain_read(s, timeout=read_seconds)
        lines = data.decode("utf-8", errors="replace").splitlines()
        result = []
        if as_json:
            for ev in parse_lines_to_events(lines):
                if ev['type'] == 'state':
                    result.append(json.dumps(ev, ensure_ascii=False))
                    recieved_state_info = True
        else:
            if len(lines) > 0 and len(lines[0]) > 0 and lines[0][0] == 'M':
                result = parse_state_lines(lines)
                recieved_state_info = True
        if recieved_state_info == True:
            break

    s.close()
    return result

    
# -----------------------------
# Command wrappers (with --json on every cmd)
# -----------------------------
def _send_and_print(ctx, line_to_send, read_seconds, as_json, read_back=True):
    s, _ = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    send_line(s, line_to_send + "\n")
    data = drain_read(s, timeout=read_seconds) if read_back else b""
    s.close()
    if as_json:
        lines = data.decode("utf-8", errors="replace").splitlines()
        for ev in parse_lines_to_events(lines):
            print(json.dumps(ev, ensure_ascii=False))
    else:
        print_lines("", data)

def xdr_tune(ctx, khz, read_seconds, as_json):
    _send_and_print(ctx, f"T{khz}", read_seconds, as_json)

def xdr_bandwidth(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"W{code}", read_seconds, as_json)


def xdr_filter(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"F{code}", read_seconds, as_json)

def xdr_mode(ctx, mode, read_seconds, as_json):
    _send_and_print(ctx, f"M{mode}", read_seconds, as_json)


def xdr_volume(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Y{value}", read_seconds, as_json)


def xdr_deemp(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"D{value}", read_seconds, as_json)


def xdr_agc(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"A{value}", read_seconds, as_json)


def xdr_antenna(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Z{value}", read_seconds, as_json)


def xdr_gain(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"G{value:02d}", read_seconds, as_json)

def xdr_daa(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"V{value}", read_seconds, as_json)


def xdr_squelch(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Q{value}", read_seconds, as_json)


def xdr_rotator(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"C{value}", read_seconds, as_json)

def xdr_interval(ctx, sampling, detector, read_seconds, as_json):
    line = f"I{sampling},{detector}" if detector is not None else f"I{sampling}"
    _send_and_print(ctx, line, read_seconds, as_json)


def xdr_init_cmd(ctx, read_seconds, as_json):
    _send_and_print(ctx, "x", read_seconds, as_json)


def xdr_shutdown(ctx, read_seconds, as_json):
    _send_and_print(ctx, "X", read_seconds, as_json)

def xdr_init_full(ctx, mode, volume, deemp, agc, if_filter, bandwidth, antenna, gain, daa,
              squelch, rotator, sampling, detector, freq_khz, status, read_seconds, as_json):
    s, _ = connect_and_auth(ctx.obj["host"], ctx.obj["port"], ctx.obj["password"])
    cmds = [
        "x",  # expect 'OK'
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
        for ev in parse_lines_to_events(data.decode("utf-8", errors="replace").splitlines()):
            print(json.dumps(ev, ensure_ascii=False))
    else:
        print_lines("", data)

if __name__ == "__main__":
    cli()

