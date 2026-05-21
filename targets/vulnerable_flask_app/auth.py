"""Authentication and profile endpoints — contains an IDOR vulnerability.

The `login_required` decorator confirms a session is logged in but does
NOT enforce that the user is authorized for the requested resource.
"""

from functools import wraps

from flask import Blueprint, request, jsonify, session, abort


auth_bp = Blueprint("auth", __name__)


# In-memory user store for the demo.
_USERS = {
    1: {"id": 1, "name": "alice", "email": "alice@example.com", "ssn": "111-11-1111"},
    2: {"id": 2, "name": "bob", "email": "bob@example.com", "ssn": "222-22-2222"},
    3: {"id": 3, "name": "admin", "email": "root@example.com", "ssn": "999-99-9999"},
}


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        # Only checks that a session exists. Crucially, does NOT verify
        # that the logged-in user is allowed to access the requested
        # resource — this gap enables IDOR in the profile endpoint.
        if "user_id" not in session:
            abort(401)
        return view(*args, **kwargs)

    return wrapper


@auth_bp.route("/login", methods=["POST"])
def login():
    body = request.get_json(silent=True) or {}
    name = body.get("name")
    for uid, u in _USERS.items():
        if u["name"] == name:
            session["user_id"] = uid
            return jsonify({"ok": True, "user_id": uid})
    return jsonify({"ok": False}), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.pop("user_id", None)
    return jsonify({"ok": True})


@auth_bp.route("/api/users/<int:user_id>/profile")
@login_required
def get_profile(user_id):
    # VULN-005 (IDOR): login_required only ensures a session exists.
    # There is NO check that session["user_id"] == user_id. Any logged-in
    # user can read /api/users/3/profile and obtain the admin's SSN.
    if session["user_id"] != user_id:
        abort(403)
    user = _USERS.get(user_id)
    if user is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(user)


@auth_bp.route("/api/me/profile")
@login_required
def get_my_profile():
    # SAFE: uses session-derived ID directly. False-positive trap for the
    # "profile lookup by ID" pattern — the input comes from session, not
    # the URL.
    user = _USERS.get(session["user_id"])
    return jsonify(user)
