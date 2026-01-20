import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

ALG = "ECDSA_P256_SHA256"

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed:\n  {' '.join(cmd)}\n\nSTDERR:\n{p.stderr.decode(errors='ignore')}")
    return p.stdout

def openssl_pubkey_der_from_priv(priv_pem: Path) -> bytes:
    return run(["openssl", "pkey", "-in", str(priv_pem), "-pubout", "-outform", "DER"])

def openssl_sign_sha256(priv_pem: Path, data: bytes) -> bytes:
    # produces DER-encoded ECDSA signature
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        data_path = td / "data.txt"
        sig_path = td / "sig.der"
        data_path.write_bytes(data)
        run(["openssl", "dgst", "-sha256", "-sign", str(priv_pem), "-out", str(sig_path), str(data_path)])
        return sig_path.read_bytes()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def cert_payload_string(key_id, channel, not_before, not_after, pubkey_der_b64) -> str:
    lines = [
        "CICADA-CERT-v1",
        f"key_id={key_id}",
        f"alg={ALG}",
        f"channel={channel}",
        f"not_before={not_before}",
        f"not_after={not_after}",
        f"pubkey_der_b64={pubkey_der_b64}",
        ""
    ]
    return "\n".join(lines)

def manifest_payload_string(version, secure_version, url, size, sha256_hex, channel, key_id) -> str:
    lines = [
        "CICADA-MANIFEST-v1",
        f"version={version}",
        f"secure_version={secure_version}",
        f"url={url}",
        f"size={size}",
        f"sha256={sha256_hex}",
        f"channel={channel}",
        f"key_id={key_id}",
        ""
    ]
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root-priv", required=True, help="Root private key PEM")
    ap.add_argument("--release-priv", required=True, help="Release private key PEM")
    ap.add_argument("--bin", required=True, help="Built firmware .bin")
    ap.add_argument("--out-dir", required=True, help="Server files dir (e.g., tools/ota_server/files)")
    ap.add_argument("--version", required=True)
    ap.add_argument("--secure-version", type=int, required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--channel", default="stable")
    ap.add_argument("--key-id", default="stable-2026-01")
    ap.add_argument("--not-before", default="2026-01-01T00:00:00Z")
    ap.add_argument("--not-after", default="2026-12-31T23:59:59Z")
    args = ap.parse_args()

    root_priv = Path(args.root_priv).resolve()
    release_priv = Path(args.release_priv).resolve()
    src_bin = Path(args.bin).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not root_priv.exists(): raise SystemExit(f"Missing: {root_priv}")
    if not release_priv.exists(): raise SystemExit(f"Missing: {release_priv}")
    if not src_bin.exists(): raise SystemExit(f"Missing: {src_bin}")

    # 1) Copy firmware to server folder as firmware.bin
    fw_path = out_dir / "firmware.bin"
    shutil.copy2(src_bin, fw_path)

    # 2) Compute size + sha256 of firmware.bin
    size = fw_path.stat().st_size
    sha = sha256_file(fw_path)

    # 3) Build release cert (root-signed)
    pub_der = openssl_pubkey_der_from_priv(release_priv)
    pub_der_b64 = b64e(pub_der)

    cert_payload = cert_payload_string(
        key_id=args.key_id,
        channel=args.channel,
        not_before=args.not_before,
        not_after=args.not_after,
        pubkey_der_b64=pub_der_b64
    ).encode("utf-8")

    cert_sig_der = openssl_sign_sha256(root_priv, cert_payload)
    cert_sig_b64 = b64e(cert_sig_der)

    release_cert = {
        "key_id": args.key_id,
        "alg": ALG,
        "channel": args.channel,
        "not_before": args.not_before,
        "not_after": args.not_after,
        "pubkey_der_b64": pub_der_b64,
        "sig_b64": cert_sig_b64
    }

    # 4) Manifest signature (release-signed)
    mani_payload = manifest_payload_string(
        version=args.version,
        secure_version=args.secure_version,
        url=args.url,
        size=size,
        sha256_hex=sha,
        channel=args.channel,
        key_id=args.key_id
    ).encode("utf-8")

    mani_sig_der = openssl_sign_sha256(release_priv, mani_payload)
    mani_sig_b64 = b64e(mani_sig_der)

    manifest = {
        "version": args.version,
        "secure_version": int(args.secure_version),
        "url": args.url,
        "size": int(size),
        "sha256": sha,
        "cicada": {
            "channel": args.channel,
            "release_cert": release_cert,
            "manifest_sig_b64": mani_sig_b64
        }
    }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("OK")
    print(" firmware:", fw_path)
    print(" manifest:", manifest_path)
    print(" size:", size)
    print(" sha256:", sha)
    print(" channel:", args.channel, " key_id:", args.key_id)

if __name__ == "__main__":
    main()
