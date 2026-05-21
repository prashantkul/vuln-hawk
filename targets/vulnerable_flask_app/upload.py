"""File upload and download — contains a path traversal sink alongside a
properly mitigated upload using werkzeug.secure_filename.
"""

import os

from flask import Blueprint, request, send_file, jsonify, abort
from werkzeug.utils import secure_filename


upload_bp = Blueprint("upload", __name__)

UPLOAD_DIR = os.environ.get("APP_UPLOAD_DIR", "/tmp/vuln_demo_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@upload_bp.route("/upload", methods=["POST"])
def upload_file():
    # SAFE: secure_filename strips path separators and resolves `..`
    # before the join. False-positive trap for the "user-controlled
    # filename passed to os.path.join" pattern.
    f = request.files.get("file")
    if f is None or not f.filename:
        return jsonify({"error": "no file"}), 400
    safe_name = secure_filename(f.filename)
    if not safe_name:
        return jsonify({"error": "invalid filename"}), 400
    dest = os.path.join(UPLOAD_DIR, safe_name)
    f.save(dest)
    return jsonify({"ok": True, "name": safe_name})


@upload_bp.route("/download")
def download_file():
    # VULN-003 (Path Traversal): request.args.get("filename") is joined
    # to UPLOAD_DIR with no validation. An attacker can request
    # ?filename=../../../../etc/passwd and os.path.join happily walks
    # outside UPLOAD_DIR (os.path.join("/tmp/x", "../etc/passwd") yields
    # "/tmp/x/../etc/passwd", which send_file then resolves and serves).
    name = request.args.get("filename", "")
    if not name:
        abort(400)
    path = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not path.startswith(os.path.realpath(UPLOAD_DIR) + os.sep):
        abort(403)
    return send_file(path)
