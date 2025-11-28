#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from flask import Flask, jsonify, request, make_response
from functools import wraps
import os
import json

def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    if request.method == 'OPTIONS':
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

# Import XDR core functions directly
from xdr_core import (
    xdr_status, xdr_listen, xdr_raw, xdr_scan, xdr_init_full,
    xdr_tune, xdr_bandwidth, xdr_filter, xdr_mode, xdr_volume, xdr_deemp,
    xdr_agc, xdr_antenna, xdr_gain, xdr_daa, xdr_squelch, xdr_rotator,
    xdr_interval, xdr_init_cmd, xdr_shutdown
)

app = Flask(__name__)

# CORS middleware
@app.after_request
def after_request(response):
    return add_cors_headers(response)

# Configuration
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5000

# Default configuration for up to 4 XDRD hosts
DEFAULT_XDRD_CONFIGS = [
    {"host": "100.127.46.12", "port": 7373, "name": "XDR-1"},  # Default first host
    {"host": None, "port": 7373, "name": "XDR-2"},  # Disabled by default
    {"host": None, "port": 7373, "name": "XDR-3"},  # Disabled by default
    {"host": None, "port": 7373, "name": "XDR-4"}   # Disabled by default
]

MAX_NUMBER_OF_CARDS = 4

# Get configuration from environment variables
HOST = os.environ.get("HOST", DEFAULT_HOST)
PORT = int(os.environ.get("PORT", DEFAULT_PORT))

# Load XDRD configurations from environment
XDRD_CONFIGS = []
for i in range(MAX_NUMBER_OF_CARDS):
    idx = i + 1  # 1-based index for environment variables
    host = os.environ.get(f"XDRD_{idx}_HOST", DEFAULT_XDRD_CONFIGS[i]["host"] if i < len(DEFAULT_XDRD_CONFIGS) else None)
    port = int(os.environ.get(f"XDRD_{idx}_PORT", DEFAULT_XDRD_CONFIGS[i]["port"] if i < len(DEFAULT_XDRD_CONFIGS) else 7373))
    name = os.environ.get(f"XDRD_{idx}_NAME", DEFAULT_XDRD_CONFIGS[i]["name"] if i < len(DEFAULT_XDRD_CONFIGS) else f"XDR-{idx}")
    password = os.environ.get(f"XDRD_{idx}_PASSWORD")

    if host:  # Only add if host is configured
        XDRD_CONFIGS.append({
            "id": idx,
            "host": host,
            "port": port,
            "name": name,
            "password": password
        })

if not XDRD_CONFIGS:
    raise ValueError("At least one XDRD host must be configured")

# XDR Context Manager
class XDRContext:
    _instances = {}

    @classmethod
    def get_context(cls, host_id):
        """Get or create an XDR context for the specified host ID"""
        if host_id not in cls._instances:
            config = next((c for c in XDRD_CONFIGS if c["id"] == host_id), None)
            if not config:
                raise ValueError(f"No configuration found for XDRD host ID {host_id}")
            cls._instances[host_id] = cls._create_context(config)
        return cls._instances[host_id]

    @classmethod
    def _create_context(cls, config):
        """Create a new XDR context from config"""
        ctx = XDRContext()
        ctx.obj = {
            'host': config["host"],
            'port': config["port"],
            'password': config["password"],
            'id': config["id"],
            'name': config["name"]
        }
        return ctx

    @classmethod
    def list_contexts(cls):
        """List all configured XDR contexts"""
        return [{
            'id': ctx.obj['id'],
            'name': ctx.obj['name'],
            'host': ctx.obj['host'],
            'port': ctx.obj['port']
        } for ctx in cls._instances.values()]

    def __init__(self):
        self.obj = {}

# Initialize contexts for all configured hosts
for config in XDRD_CONFIGS:
    XDRContext.get_context(config["id"])

# API Endpoints
@app.route('/api/xdrs', methods=['GET'])
def list_xdrs():
    """List all configured XDR receivers"""
    return jsonify({
        'xdrs': XDRContext.list_contexts(),
        'count': len(XDRContext.list_contexts())
    })

@app.route('/api/status/<int:xdrid>', methods=['GET', 'OPTIONS'], defaults={'xdrid': 1})
def get_status(xdrid):
    if request.method == 'OPTIONS':
        return make_response()

    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 1.0))
        as_json = False
        result = xdr_status(xdr_ctx, read_seconds, as_json)

        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/tune/<int:khz>', methods=['POST', 'OPTIONS'])
@app.route('/api/tune/<int:khz>', methods=['POST', 'OPTIONS'], defaults={'xdrid': 1})
def tune(xdrid, khz):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_tune(xdr_ctx, khz, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/bandwidth/<int:code>', methods=['POST', 'OPTIONS'])
@app.route('/api/bandwidth/<int:code>', methods=['POST', 'OPTIONS'], defaults={'xdrid': 1})
def set_bandwidth(xdrid, code):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_bandwidth(xdr_ctx, code, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/filter/<int:code>', methods=['POST', 'OPTIONS'])
@app.route('/api/filter/<int:code>', methods=['POST', 'OPTIONS'], defaults={'xdrid': 1})
def set_filter(xdrid, code):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_filter(xdr_ctx, code, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/mode/<int:mode>', methods=['POST'])
@app.route('/api/mode/<int:mode>', methods=['POST'], defaults={'xdrid': 1})
def set_mode(xdrid, mode):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_mode(xdr_ctx, mode, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/volume/<int:value>', methods=['POST'])
@app.route('/api/volume/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_volume(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_volume(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/deemp/<int:value>', methods=['POST'])
@app.route('/api/deemp/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_deemp(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_deemp(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/agc/<int:value>', methods=['POST'])
@app.route('/api/agc/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_agc(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_agc(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/antenna/<int:value>', methods=['POST'])
@app.route('/api/antenna/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_antenna(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_antenna(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/gain/<int:value>', methods=['POST'])
@app.route('/api/gain/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_gain(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_gain(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/daa/<int:value>', methods=['POST'])
@app.route('/api/daa/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_daa(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_daa(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/squelch/<int:value>', methods=['POST'])
@app.route('/api/squelch/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_squelch(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_squelch(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/rotator/<int:value>', methods=['POST'])
@app.route('/api/rotator/<int:value>', methods=['POST'], defaults={'xdrid': 1})
def set_rotator(xdrid, value):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_rotator(xdr_ctx, value, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/interval', methods=['POST'])
@app.route('/api/interval', methods=['POST'], defaults={'xdrid': 1})
def set_interval(xdrid):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        data = request.get_json()
        if not data or 'interval' not in data:
            return jsonify({"error": "Missing interval parameter"}), 400

        interval = int(data['interval'])
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_interval(xdr_ctx, interval, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/init', methods=['POST'])
@app.route('/api/init', methods=['POST'], defaults={'xdrid': 1})
def init(xdrid):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_init_cmd(xdr_ctx, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/shutdown', methods=['POST'])
@app.route('/api/shutdown', methods=['POST'], defaults={'xdrid': 1})
def shutdown(xdrid):
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_shutdown(xdr_ctx, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

@app.route('/api/<int:xdrid>/scan', methods=['GET'])
@app.route('/api/scan', methods=['GET'], defaults={'xdrid': 1})
def scan(xdrid):
    if request.method == 'OPTIONS':
        return make_response()
    try:
        xdr_ctx = XDRContext.get_context(xdrid)
        read_seconds = float(request.args.get('read_seconds', 0.6))
        as_json = False
        result = xdr_scan(xdr_ctx, read_seconds, as_json)
        return jsonify(result)
    except ValueError as e:
        return jsonify({"error": str(e)}), 404

if __name__ == '__main__':
    app.run(host=HOST,
            port=PORT,
            debug=os.environ.get('DEBUG', 'false').lower() == 'true')
