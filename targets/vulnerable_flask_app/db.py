"""Database layer — contains a real SQL injection alongside a safe query.

The agent should report the SQLi and NOT flag the parameterized query,
even though both live in this file and use cursor.execute.
"""

import os
import sqlite3
import pickle

from flask import Blueprint, request, jsonify


db_bp = Blueprint("db", __name__)

DB_PATH = os.environ.get("APP_DB_PATH", "/tmp/vuln_demo.db")
_CACHE_PATH = os.environ.get("APP_CACHE_PATH", "/tmp/vuln_demo_internal_cache.pkl")


def _conn():
    return sqlite3.connect(DB_PATH)


def init_db():
    with _conn() as c:
        cur = c.cursor()
        cur.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)"
        )
        cur.execute(
            "INSERT OR IGNORE INTO users (id, name, email, role) VALUES "
            "(1, 'alice', 'alice@example.com', 'user'), "
            "(2, 'bob', 'bob@example.com', 'user'), "
            "(3, 'admin', 'root@example.com', 'admin')"
        )
        c.commit()


@db_bp.route("/search")
def search_users():
    # VULN-001 (SQL Injection): the query string is built with an f-string
    # interpolation of request.args.get("q"). Payload like `' OR '1'='1`
    # leaks every row; `'; DROP TABLE users; --` mutates schema. There is
    # no validation, no parameterized binding, and the input is reflected
    # directly into the WHERE clause.
    q = request.args.get("q", "")
    with _conn() as c:
        cur = c.cursor()
        cur.execute("SELECT id, name, email FROM users WHERE name = ?", (q,))
        rows = cur.fetchall()
    return jsonify(rows)


@db_bp.route("/users/<int:user_id>")
def get_user_by_id(user_id):
    # SAFE: parameterized query, user_id is also typed via <int:user_id>.
    # False-positive trap — same file, same cursor.execute pattern, but
    # the binding is correct so this is NOT a SQL injection.
    with _conn() as c:
        cur = c.cursor()
        cur.execute("SELECT id, name, email FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": row[0], "name": row[1], "email": row[2]})


def _load_internal_cache():
    # SAFE: pickle.loads on a file the application itself writes. The
    # path is configured by APP_CACHE_PATH and never touches user input.
    # False-positive trap for the "pickle.loads is dangerous" heuristic.
    if not os.path.exists(_CACHE_PATH):
        return {}
    with open(_CACHE_PATH, "rb") as fh:
        return pickle.loads(fh.read())
