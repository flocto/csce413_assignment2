#!/usr/bin/env python3

import os
import time

from flask import Flask, jsonify, make_response, redirect, render_template, request, send_from_directory

from logger import create_logger

HTTP_PORT = int(os.environ.get("HONEYPOT_HTTP_PORT", "80"))
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "http_templates")
STATE = {"sessions": {}, "ip_counts": {}}
START_TS = time.time()

app = Flask(__name__, template_folder=TEMPLATE_DIR)
log = create_logger()


def get_sid():
    sid = request.cookies.get("hp_sid", "")
    if not sid:
        STATE["ip_counts"][request.remote_addr] = STATE["ip_counts"].get(
            request.remote_addr, 0) + 1
        sid = f"{request.remote_addr}:{request.environ.get('REMOTE_PORT', 0)}:{STATE['ip_counts'][request.remote_addr]}"
        STATE["sessions"][sid] = {"ip": request.remote_addr}
    return sid


def log_request():
    sid = get_sid()
    body_parsed = {}
    if request.content_type and "application/x-www-form-urlencoded" in request.content_type:
        body_parsed = {k: v for k, v in request.form.items()}
    elif request.files:
        body_parsed = {"filenames": [
            f.filename for f in request.files.values()]}
    elif request.data:
        body_parsed = {"raw": request.data.decode("utf-8", "replace")}

    event = {
        "type": "http_request",
        "src_ip": request.remote_addr,
        "src_port": request.environ.get("REMOTE_PORT"),
        "version": request.environ.get("SERVER_PROTOCOL", ""),
        "session": sid,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "auth": request.headers.get("Authorization", ""),
        "headers": {k.lower(): v for k, v in request.headers.items() if k.lower() not in ["user-agent", "authorization"]},
        "body": body_parsed,
    }
    if request.query_string:
        event["query"] = request.query_string.decode("utf-8", "replace")
    if request.path in {"/login", "/admin", "/wp-login.php", "/phpmyadmin"}:
        event["tag"] = "credential_probe"
    if "username" in body_parsed or "password" in body_parsed:
        event["creds"] = {
            "username": body_parsed.get("username", ""),
            "password": body_parsed.get("password", ""),
        }
    if "filenames" in body_parsed and body_parsed["filenames"]:
        event["tag"] = "file_upload"
    log(event)
    return sid


@app.before_request
def before_request():
    request.sid = log_request()


@app.after_request
def after_request(response):
    response.headers["Server"] = "Apache/2.4.52"
    response.set_cookie("hp_sid", request.sid, path="/")
    return response


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")


@app.route("/admin")
def admin():
    return redirect("/login", code=302)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/support", methods=["GET", "POST"])
def support():
    return render_template("support.html")


@app.route("/docs")
def docs():
    return render_template("docs.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/db", methods=["GET", "POST"])
@app.route("/search", methods=["GET", "POST"])
def db_query():
    return render_template("db_query.html")


@app.route("/users", methods=["GET", "POST"])
@app.route("/user_info", methods=["GET", "POST"])
def users():
    return render_template("user_info.html")


@app.route("/files")
def files():
    return render_template("files.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    return render_template("file_upload.html")


@app.route("/health")
def health():
    return make_response("ok", 200)


@app.route("/robots.txt")
def robots():
    return make_response("User-agent: *\nDisallow: /admin\nDisallow: /backup\n", 200)


@app.route("/favicon.ico")
def favicon():
    # return some random image xd
    return send_from_directory(
        TEMPLATE_DIR,
        "favicon.ico",
        mimetype="image/vnd.microsoft.icon",
    )


@app.route("/api/status")
def api_status():
    return jsonify({"ok": True, "service": "portal", "uptime_s": int(time.time() - START_TS)})


@app.route("/api/users")
def api_users():
    return jsonify({"ok": True, "users": ["alice", "bob", "carol", "dave"]})


@app.route("/api/login", methods=["POST", "GET"])
def api_login():
    return jsonify({"ok": False, "error": "invalid_credentials"}), 401


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "")
    return jsonify({"ok": True, "q": q, "results": []})


@app.route("/static/<path:filename>")
def static_files(filename):
    return send_from_directory(TEMPLATE_DIR, filename)


def run_http_honeypot():
    log({"type": "start", "proto": "http", "port": HTTP_PORT})
    app.run(host="0.0.0.0", port=HTTP_PORT, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_http_honeypot()
