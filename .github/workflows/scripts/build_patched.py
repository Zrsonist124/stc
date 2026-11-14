#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CI job: watch the upstream ST-Ctrl repo, rebuild its arm64 apk with our
token-counter fix and our own update-channel slug, sign it, publish a release.

Runs inside GitHub Actions. Required env:
  GITHUB_TOKEN       auto-provided
  GITHUB_REPOSITORY  auto-provided (owner/repo)
  KEYSTORE_B64       base64 of fix.keystore  (repository secret)
Optional env:
  UPSTREAM_REPO      default wancDDY/ST-Ctrl
  KEYSTORE_PASS      default stctrlfix
  KEY_ALIAS          default stctrlfix
"""
import base64
import glob
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib

UPSTREAM = os.environ.get("UPSTREAM_REPO", "wancDDY/ST-Ctrl")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
KS_PASS = os.environ.get("KEYSTORE_PASS", "stctrlfix")
KS_ALIAS = os.environ.get("KEY_ALIAS", "stctrlfix")
MARKER = "ST-Ctrl fix: cache key"
OLD_SLUG = b"wancDDY/ST-Ctrl"
SLUG_LEN = len(OLD_SLUG)

OVERRIDE = """

// ST-Ctrl fix: cache key must depend on the serialized request body, not String(body).
// Appended so every byte of the shipped file (and therefore any patch guard) stays intact.
stctrlTokenCountKey = function (model, body) {
    const stctrlBodyText = typeof body === 'string' ? body : JSON.stringify(body);
    return createHash('sha1').update(String(model)).update('\\0').update(stctrlBodyText).digest('hex');
};
"""


def log(*a):
    print(*a, flush=True)


def api(path, method="GET", data=None, extra=None):
    url = path if path.startswith("http") else "https://api.github.com" + path
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"token {TOKEN}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "stctrl-sync")
    for k, v in (extra or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"raw": body[:300]}


def find_tool(name):
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or ""
    cands = glob.glob(os.path.join(home, "build-tools", "*", name))
    if not cands:
        cands = glob.glob(os.path.join(home, "build-tools", "*", name + ".exe"))
    if not cands:
        raise SystemExit(f"cannot find {name} under {home}")
    cands.sort(key=lambda p: [int(x) if x.isdigit() else 0 for x in re.split(r"[./\\-]", p)])
    return cands[-1]


def verify_dex_order(data):
    """Android rejects a dex whose string_ids table is out of UTF-16 order."""
    import struct
    n = struct.unpack_from("<I", data, 0x38)[0]
    off = struct.unpack_from("<I", data, 0x3C)[0]

    def read(o):
        i = o
        while data[i] & 0x80:
            i += 1
        i += 1
        end = data.index(b"\x00", i)
        raw = data[i:end].replace(b"\xc0\x80", b"\x00")
        return raw.decode("utf-8", "surrogatepass")

    prev = prev_key = None
    for k in range(n):
        s = read(struct.unpack_from("<I", data, off + 4 * k)[0])
        key = s.encode("utf-16-be", "surrogatepass")
        if prev_key is not None and key < prev_key:
            raise SystemExit(f"dex string order broken: {prev!r} then {s!r} - "
                             "owner name must sort after 'SillyTavern' (first letter > 'S')")
        prev, prev_key = s, key


def patch_dex(data, old_slug, new_slug):
    """Replace the channel slug, repair the dex header, verify string order."""
    count = data.count(old_slug)
    if not count:
        return data, 0
    b = bytearray(data.replace(old_slug, new_slug))
    b[12:32] = hashlib.sha1(bytes(b[32:])).digest()
    b[8:12] = (zlib.adler32(bytes(b[12:])) & 0xFFFFFFFF).to_bytes(4, "little")
    out = bytes(b)
    verify_dex_order(out)
    return out, count


def patch_core(src_zip, dst_zip):
    with zipfile.ZipFile(src_zip) as zin:
        text = zin.read("src/endpoints/tokenizers.js").decode("utf-8")
        if MARKER in text:
            fixed = None
        elif "function stctrlTokenCountKey(model, text)" in text:
            fixed = (text + OVERRIDE).encode("utf-8")
        else:
            raise SystemExit("tokenizers.js anchor not found - upstream layout changed")
        with zipfile.ZipFile(dst_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
            for info in zin.infolist():
                data = fixed if (fixed and info.filename == "src/endpoints/tokenizers.js") else zin.read(info.filename)
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zout.writestr(zi, data)


def main():
    if not REPO:
        raise SystemExit("GITHUB_REPOSITORY missing")
    slug = REPO.encode()
    if len(slug) != SLUG_LEN:
        raise SystemExit(f"repo slug '{REPO}' is {len(slug)} chars, must be {SLUG_LEN} to patch the dex safely")

    # latest upstream app release
    st, rels = api(f"/repos/{UPSTREAM}/releases?per_page=30")
    if st != 200:
        raise SystemExit(f"upstream lookup failed: {st}")
    up = None
    for r in rels:
        if not r["tag_name"].startswith("v"):
            continue
        asset = next((a for a in r.get("assets", []) if a["name"].endswith("-arm64.apk")), None)
        if asset:
            up = (r, asset)
            break
    if not up:
        raise SystemExit("no upstream arm64 release found")
    up_rel, up_asset = up
    tag = up_rel["tag_name"]
    log(f"upstream latest: {tag}  asset {up_asset['name']} ({up_asset['size']} bytes)")

    # already published?
    st, mine = api(f"/repos/{REPO}/releases/tags/{tag}")
    if st == 200:
        log(f"release {tag} already exists here - nothing to do")
        return 0
    if st not in (404,):
        log(f"warning: our release lookup returned {st}")

    tmp = tempfile.mkdtemp()
    try:
        # download upstream apk
        apk_in = os.path.join(tmp, "official.apk")
        log("downloading upstream apk ...")
        req = urllib.request.Request(up_asset["browser_download_url"],
                                     headers={"User-Agent": "stctrl-sync", "Accept": "application/octet-stream"})
        with urllib.request.urlopen(req, timeout=600) as r, open(apk_in, "wb") as f:
            shutil.copyfileobj(r, f, 1 << 20)
        log(f"  {os.path.getsize(apk_in)} bytes")

        # core patch
        core_in = os.path.join(tmp, "core.zip")
        core_out = os.path.join(tmp, "core-new.zip")
        with zipfile.ZipFile(apk_in) as z:
            with z.open("assets/core/tavern-core.zip") as s, open(core_in, "wb") as d:
                shutil.copyfileobj(s, d, 1 << 20)
        patch_core(core_in, core_out)
        log(f"core patched -> {os.path.getsize(core_out)} bytes")

        # repack apk + dex slug
        apk_unsigned = os.path.join(tmp, "unsigned.apk")
        hits = 0
        with zipfile.ZipFile(apk_in) as zin, zipfile.ZipFile(apk_unsigned, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zout:
            for info in zin.infolist():
                if info.filename.startswith("META-INF/") and info.filename.upper().endswith((".RSA", ".DSA", ".EC", ".SF", ".MF")):
                    continue
                if info.filename == "assets/core/tavern-core.zip":
                    data = open(core_out, "rb").read()
                else:
                    data = zin.read(info.filename)
                    if info.filename.startswith("classes") and info.filename.endswith(".dex"):
                        data, n = patch_dex(data, OLD_SLUG, slug)
                        hits += n
                zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
                zi.compress_type = info.compress_type
                zi.external_attr = info.external_attr
                zi.internal_attr = info.internal_attr
                zi.create_system = info.create_system
                zout.writestr(zi, data)
        if hits == 0:
            raise SystemExit("update url not found in dex")
        log(f"dex: {hits} occurrences of {OLD_SLUG.decode()} -> {REPO}")

        # sign
        ks = os.path.join(tmp, "sign.keystore")
        b64 = os.environ["KEYSTORE_B64"].strip()
        open(ks, "wb").write(base64.b64decode(b64))
        aligned = os.path.join(tmp, "aligned.apk")
        subprocess.run([find_tool("zipalign"), "-p", "-f", "4", apk_unsigned, aligned], check=True)
        out = os.path.join(tmp, os.path.basename(up_asset["name"]).replace("-tokenfix", ""))
        subprocess.run([find_tool("apksigner"), "sign", "--ks", ks,
                        "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KS_PASS}",
                        "--ks-key-alias", KS_ALIAS, "--out", out, aligned], check=True)
        log(f"signed -> {out} ({os.path.getsize(out)} bytes)")

        # create release
        st, created = api(f"/repos/{REPO}/releases", method="POST",
                          data=json.dumps({
                              "tag_name": tag,
                              "name": f"ST-Ctrl {tag} (token fix)",
                              "body": f"Auto-built from upstream {UPSTREAM} {tag}\n\n"
                                      f"- appended token-counter fix\n- update channel: {REPO}",
                              "draft": False,
                              "prerelease": False,
                          }).encode())
        if st not in (200, 201):
            raise SystemExit(f"create release failed: {st} {created}")
        rid = created["id"]

        # upload asset
        name = os.path.basename(out)
        log(f"uploading {name} ...")
        conn = http.client.HTTPSConnection("uploads.github.com", timeout=900)
        conn.putrequest("POST", f"/repos/{REPO}/releases/{rid}/assets?name={urllib.parse.quote(name)}")
        conn.putheader("Authorization", f"token {TOKEN}")
        conn.putheader("User-Agent", "stctrl-sync")
        conn.putheader("Content-Type", "application/octet-stream")
        conn.putheader("Content-Length", str(os.path.getsize(out)))
        conn.endheaders()
        with open(out, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                conn.send(chunk)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", "replace")
        conn.close()
        if resp.status not in (200, 201):
            raise SystemExit(f"upload failed: {resp.status} {body[:300]}")
        log("published:", json.loads(body)["browser_download_url"])
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
