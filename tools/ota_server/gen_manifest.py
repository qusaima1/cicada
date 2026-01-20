import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="Path to built .bin (e.g., build_1_0_2/cicada.bin)")
    ap.add_argument("--version", required=True, help="Semver, e.g. 1.0.2")
    ap.add_argument("--secure-version", type=int, required=True, help="Monotonic security version")
    ap.add_argument("--url", required=True, help="Firmware URL served to device (https://...)")
    ap.add_argument("--out-dir", required=True, help="Output directory (e.g., tools/ota_server/files)")
    args = ap.parse_args()

    src = Path(args.bin).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if not src.exists():
        raise SystemExit(f"ERROR: input bin not found: {src}")

    # Copy/rename to firmware.bin
    fw_path = out_dir / "firmware.bin"
    shutil.copy2(src, fw_path)

    size = fw_path.stat().st_size
    sha = sha256_file(fw_path)

    manifest = {
        "version": args.version,
        "secure_version": int(args.secure_version),
        "url": args.url,
        "size": size,
        "sha256": sha
    }

    manifest_path = out_dir / "manifest.json"
    with manifest_path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    print("OK")
    print(" firmware:", fw_path)
    print(" manifest:", manifest_path)
    print(" size:", size)
    print(" sha256:", sha)

if __name__ == "__main__":
    main()
