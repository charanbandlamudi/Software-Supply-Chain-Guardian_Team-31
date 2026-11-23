"""Smoke test used by the Guardian's sandbox validation agent."""
import io
import sys

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from app import app  # noqa: E402

c = app.test_client()
assert c.get("/").json == {"status": "ok"}
r = c.post("/upload", data={"file": (io.BytesIO(b"hello"), "a.txt")}, content_type="multipart/form-data")
assert r.json == {"name": "a.txt", "size": 5}, r.data
print("SMOKE OK")
