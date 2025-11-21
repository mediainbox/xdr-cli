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
DEFAULT_XDRD_HOST = "100.127.46.12"
DEFAULT_XDRD_PORT = 7373

# Get configuration from environment variables
HOST = os.environ.get("HOST", DEFAULT_HOST)
PORT = int(os.environ.get("PORT", DEFAULT_PORT))
XDRD_HOST = os.environ.get("XDRD_HOST", DEFAULT_XDRD_HOST)
XDRD_PORT = int(os.environ.get("XDRD_PORT", DEFAULT_XDRD_PORT))
XDRD_PASSWORD = os.environ.get("XDRD_PASSWORD")

# Create context for XDR functions
class XDRContext:
    obj = {}
    def __init__(self, host, port, password=None):
        self.obj['host'] = host
        self.obj['port'] = port
        self.obj['password'] = password

# Create context for XDR functions
xdr_ctx = XDRContext(XDRD_HOST, XDRD_PORT, XDRD_PASSWORD)

# API Endpoints
@app.route('/api/status/<int:status_id>', methods=['GET', 'OPTIONS'])
def get_status(status_id=None):
    if request.method == 'OPTIONS':
        return make_response()

    read_seconds = float(request.args.get('read_seconds', 1.0))
    as_json = False
    result = xdr_status(xdr_ctx, read_seconds, as_json)
    if status_id is not None:
        if 0 <= status_id:
            return jsonify(result)
        return jsonify({"error": "Status ID out of range"}), 404
    return jsonify(result)

@app.route('/api/tune/<int:khz>', methods=['POST', 'OPTIONS'])
def tune(khz):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_tune(xdr_ctx, khz, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/bandwidth/<int:code>', methods=['POST', 'OPTIONS'])
def set_bandwidth(code):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_bandwidth(xdr_ctx, code, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/filter/<int:code>', methods=['POST', 'OPTIONS'])
def set_filter(code):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_filter(xdr_ctx, code, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/mode/<int:mode>', methods=['POST'])
def set_mode(mode):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_mode(xdr_ctx, mode, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/volume/<int:value>', methods=['POST'])
def set_volume(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_volume(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/deemp/<int:value>', methods=['POST'])
def set_deemp(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_deemp(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/agc/<int:value>', methods=['POST'])
def set_agc(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_agc(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/antenna/<int:value>', methods=['POST'])
def set_antenna(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_antenna(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/gain/<int:value>', methods=['POST'])
def set_gain(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_gain(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/daa/<int:value>', methods=['POST'])
def set_daa(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_daa(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/squelch/<int:value>', methods=['POST'])
def set_squelch(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_squelch(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/rotator/<int:value>', methods=['POST'])
def set_rotator(value):
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_rotator(xdr_ctx, value, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/interval', methods=['POST'])
def set_interval():
    data = request.get_json()
    sampling = data.get('sampling')
    detector = data.get('detector')
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False

    result = xdr_interval(xdr_ctx, sampling, detector, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/init', methods=['POST'])
def init():
    read_seconds = float(request.args.get('read_seconds', 1.0))
    as_json = False
    result = xdr_init_cmd(xdr_ctx, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/shutdown', methods=['POST'])
def shutdown():
    read_seconds = float(request.args.get('read_seconds', 0.6))
    as_json = False
    result = xdr_shutdown(xdr_ctx, read_seconds, as_json)
    return jsonify(result)

@app.route('/api/scan', methods=['GET'])
def scan():
    read_seconds = float(request.args.get('read_seconds', 5.0))
    as_json = False
    result = xdr_scan(xdr_ctx, read_seconds, as_json)
    return jsonify(result)

if __name__ == '__main__':
    app.run(host=HOST,
            port=PORT,
            debug=os.environ.get('DEBUG', 'false').lower() == 'true')
