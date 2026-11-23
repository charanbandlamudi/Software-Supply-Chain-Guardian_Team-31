"""Guardian demo app: small Flask API with an upload route and an outbound HTTP call."""
import os

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(status="ok")


@app.post("/upload")
def upload():
    f = request.files.get("file")          # multipart parsing (Werkzeug form parser)
    return jsonify(name=f.filename if f else None, size=len(f.read()) if f else 0)


@app.get("/proxy")
def proxy():
    url = os.environ.get("UPSTREAM", "https://example.org")
    return jsonify(code=requests.get(url, timeout=5).status_code)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=os.environ.get("DEBUG") == "1")
