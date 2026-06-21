"""Small download helper shared by the external benchmark builders.

Fetches a URL once, caches the bytes next to the builder so the test set can be
rebuilt offline, and returns decoded text. No third-party dependencies.
"""
import os
import urllib.request

_UA = "calus-benchmark/1.0 (+https://github.com/wholesphereai/calus)"


def fetch_text(url, cache=None, timeout=60):
    """Return the text at `url`. If `cache` exists, read it; else download + save."""
    if cache and os.path.exists(cache) and os.path.getsize(cache) > 0:
        with open(cache, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8", errors="ignore")
    if cache:
        with open(cache, "w", encoding="utf-8") as f:
            f.write(data)
    return data
