"""Miscellaneous endpoints — command injection, SSRF, and false-positive
traps that exercise the agent's data flow tracing.
"""

import os
import subprocess

import ipaddress
import socket
import urllib.parse

import requests
from flask import Blueprint, request, jsonify, abort
from werkzeug.utils import secure_filename


utils_bp = Blueprint("utils", __name__)


@utils_bp.route("/convert", methods=["POST"])
def convert_file():
    # VULN-002 (Command Injection): the user-controlled `filename` field
    # is interpolated into a shell command and shell=True is set. A
    # filename like `foo.jpg; rm -rf /tmp/anything` runs arbitrary
    # commands as the web process.
    body = request.get_json(silent=True) or {}
    filename = body.get("filename", "")
    filename = secure_filename(filename)
    if not filename:
        return jsonify({"error": "invalid filename"}), 400
    result = subprocess.run(["convert", filename, "output.pdf"], capture_output=True, text=True)
    return jsonify({"stdout": result.stdout, "stderr": result.stderr})


@utils_bp.route("/system-info")
def system_info():
    # SAFE: subprocess with hardcoded arguments, no user input reaches
    # the command. False-positive trap for the "subprocess is dangerous"
    # heuristic.
    out = subprocess.run(["uname", "-a"], capture_output=True, text=True)
    return jsonify({"info": out.stdout})


@utils_bp.route("/preview")
def preview_url():
    # VULN-007 (SSRF): the user supplies an arbitrary URL and the server
    # fetches it with no allowlist, no scheme check, and no IP filtering.
    # Attackers can reach internal services (http://169.254.169.254 for
    # cloud metadata, http://localhost:6379 for Redis, etc.).
    url = request.args.get("url", "")
    if not url:
        abort(400)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        abort(400, "Only http and https schemes are allowed")
    hostname = parsed.hostname
    if not hostname:
        abort(400, "Invalid URL")
    try:
        resolved_ips = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        abort(400, "Cannot resolve hostname")
    for entry in resolved_ips:
        ip = ipaddress.ip_address(entry[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            abort(403, "Requests to internal/private addresses are not allowed")
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return jsonify({"status": resp.status_code, "body": resp.text[:500]})


@utils_bp.route("/internal-status")
def internal_status():
    # SAFE: hardcoded URL with no user input. False-positive trap for
    # the "requests.get is SSRF-prone" heuristic.
    resp = requests.get("http://localhost:8000/healthz", timeout=2)
    return jsonify({"status": resp.status_code})


def _run_local_smoke_test():
    # SAFE: os.system call with hardcoded arguments. False-positive trap
    # for the "os.system is dangerous" heuristic.
    return os.system("echo smoke-test-ok")
