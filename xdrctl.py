#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import hashlib
import json
import re
import string
import click

from xdr_core import xdr_status, xdr_listen, xdr_raw, xdr_scan, xdr_init_full, xdr_send_and_print

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 7373  # xdrd default


# -----------------------------
# CLI
# -----------------------------
@click.group(help="xdrd CLI: AUTH via SHA1(salt+password) and ASCII commands.")
@click.option("--host", default=DEFAULT_HOST, show_default=True)
@click.option("--port", default=DEFAULT_PORT, type=int, show_default=True)
@click.option("--password", default=None, help="xdrd password (or XDRD_PASS / --password-file).")
@click.option("--password-file", type=click.Path(exists=True), default=None, help="Read password from file.")
@click.pass_context
def cli(ctx, host, port, password, password_file):
    pwd = password
    if pwd is None and password_file:
        with open(password_file, "r", encoding="utf-8", errors="ignore") as f:
            pwd = f.read().strip()
    if pwd is None:
        pwd = os.environ.get("XDRD_PASS")
    ctx.ensure_object(dict)
    ctx.obj.update(host=host, port=port, password=pwd)

# -----------------------------
# High-level commands
# -----------------------------
@cli.command(help="Show current state (reads the dump after AUTH).")
@click.option("--read-seconds", default=1.0, show_default=True, type=float, help="How long to read after AUTH.")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit JSON.")
@click.pass_context
def status(ctx, read_seconds, as_json):
    status = xdr_status(ctx, read_seconds, as_json)
    print(status)


@cli.command(help="Listen and decode events (Ctrl+C to exit).")
@click.option("--json", "as_json", is_flag=True, default=False, help="One JSON object per event.")
@click.pass_context
def listen(ctx, as_json):
    xdr_listen(ctx, as_json)

@cli.command(help="Send a raw line (no auto newline unless you include it).")
@click.argument("text", nargs=-1, required=True)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def raw(ctx, text, read_seconds, as_json):
    result = xdr_raw(ctx, text, read_seconds, as_json)
    print(result)


@cli.command(help="Send a scan command")
@click.option("--read-seconds", default=5, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=True)
@click.pass_context
def scan(ctx, read_seconds, as_json):
    result = xdr_scan(ctx, read_seconds, as_json)
    print(result)
    

@cli.command(help="Tune in kHz. Example: 101700 means 101.7 MHz.")
@click.argument("khz", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def tune(ctx, khz, read_seconds, as_json):
    _send_and_print(ctx, f"T{khz}", read_seconds, as_json)

@cli.command(help="IF bandwidth (W).")
@click.argument("code", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def bandwidth(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"W{code}", read_seconds, as_json)

@cli.command(help="IF filter (F).")
@click.argument("code", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def filter(ctx, code, read_seconds, as_json):
    _send_and_print(ctx, f"F{code}", read_seconds, as_json)

@cli.command(help="Mode (M).")
@click.argument("mode", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def mode(ctx, mode, read_seconds, as_json):
    _send_and_print(ctx, f"M{mode}", read_seconds, as_json)

@cli.command(help="Volume (Y). 0..100.")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def volume(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Y{value}", read_seconds, as_json)

@cli.command(help="De-emphasis (D).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def deemp(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"D{value}", read_seconds, as_json)

@cli.command(help="AGC (A).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def agc(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"A{value}", read_seconds, as_json)

@cli.command(help="Antenna (Z).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def antenna(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Z{value}", read_seconds, as_json)

@cli.command(help="Gain (G).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def gain(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"G{value:02d}", read_seconds, as_json)

@cli.command(help="DAA (V).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def daa(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"V{value}", read_seconds, as_json)

@cli.command(help="Squelch (Q).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def squelch(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"Q{value}", read_seconds, as_json)

@cli.command(help="Rotator (C).")
@click.argument("value", type=int)
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def rotator(ctx, value, read_seconds, as_json):
    _send_and_print(ctx, f"C{value}", read_seconds, as_json)

@cli.command(help="Interval (I). Accepts either '--sampling N --detector M' or just '--sampling N'.")
@click.option("--sampling", required=True, type=int)
@click.option("--detector", type=int, default=None, help="If omitted, send only sampling.")
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def interval(ctx, sampling, detector, read_seconds, as_json):
    line = f"I{sampling},{detector}" if detector is not None else f"I{sampling}"
    _send_and_print(ctx, line, read_seconds, as_json)

# -----------------------------
# Startup / Shutdown / Init-full
# -----------------------------
@cli.command(name="init", help="Initializer (sends 'x' and expects 'OK').")
@click.option("--read-seconds", default=1.0, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def init_cmd(ctx, read_seconds, as_json):
    _send_and_print(ctx, "x", read_seconds, as_json)

@cli.command(help="Shutdown (sends 'X').")
@click.option("--read-seconds", default=0.6, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def shutdown(ctx, read_seconds, as_json):
    _send_and_print(ctx, "X", read_seconds, as_json)

@cli.command(name="init-full", help="x + defaults (override via flags), optional tune and status.")
@click.option("--mode", default=0, show_default=True, type=int)
@click.option("--volume", default=100, show_default=True, type=int)
@click.option("--deemp", default=0, show_default=True, type=int)
@click.option("--agc", default=2, show_default=True, type=int)
@click.option("--filter", "if_filter", default=-1, show_default=True, type=int)
@click.option("--bandwidth", default=0, show_default=True, type=int)
@click.option("--antenna", default=0, show_default=True, type=int)
@click.option("--gain", default=0, show_default=True, type=int)
@click.option("--daa", default=0, show_default=True, type=int)
@click.option("--squelch", default=0, show_default=True, type=int)
@click.option("--rotator", default=0, show_default=True, type=int)
@click.option("--sampling", default=0, show_default=True, type=int)
@click.option("--detector", default=0, show_default=True, type=int)
@click.option("--freq-khz", type=int, default=None)
@click.option("--status", is_flag=True, default=False)
@click.option("--read-seconds", default=2.0, show_default=True, type=float)
@click.option("--json", "as_json", is_flag=True, default=False)
@click.pass_context
def init_full(ctx, mode, volume, deemp, agc, if_filter, bandwidth, antenna, gain, daa,
              squelch, rotator, sampling, detector, freq_khz, status, read_seconds, as_json):
    xdr_init_full(ctx, mode, volume, deemp, agc, if_filter, bandwidth, antenna, gain, daa,
              squelch, rotator, sampling, detector, freq_khz, status, read_seconds, as_json)


if __name__ == "__main__":
    cli()

