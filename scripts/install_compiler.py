#!/usr/bin/env python3
"""Install one checksum-pinned official compiler locally, without changing PATH."""

import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    config = json.loads((ROOT / "config/compiler.json").read_text())
    key = platform.system() + "-" + platform.machine()
    if key not in config["assets"]:
        raise SystemExit("Unsupported platform: " + key)
    asset = config["assets"][key]
    tools = ROOT / ".tools"
    tools.mkdir(exist_ok=True)
    binary = tools / "sing-box"
    stamp = tools / "compiler.json"
    expected_stamp = {"version": config["version"], "asset_sha256": asset["sha256"]}
    if binary.is_file() and stamp.is_file():
        installed = json.loads(stamp.read_text())
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        if all(installed.get(k) == v for k, v in expected_stamp.items()) and installed.get("binary_sha256") == digest:
            print("Compiler already verified: " + config["version"])
            return
    url = "https://github.com/SagerNet/sing-box/releases/download/v" + config["version"] + "/" + asset["name"]
    with tempfile.TemporaryDirectory(prefix="compiler-", dir=tools) as folder:
        archive = Path(folder) / asset["name"]
        subprocess.run([
            "curl", "--fail", "--location", "--silent", "--show-error",
            "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
            "--retry", "3", "--connect-timeout", "15", "--max-time", "300",
            "--max-filesize", "268435456", "--output", str(archive), url,
        ], check=True)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != asset["sha256"]:
            raise SystemExit("Compiler archive SHA-256 mismatch; nothing installed")
        member_name = asset["name"].removesuffix(".tar.gz") + "/sing-box"
        staged = Path(folder) / "sing-box"
        with tarfile.open(archive, "r:gz") as package:
            member = package.getmember(member_name)
            if not member.isfile() or member.size > 536870912:
                raise SystemExit("Unexpected compiler archive member")
            with package.extractfile(member) as source, staged.open("wb") as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    target.write(chunk)
        staged.chmod(0o755)
        first_line = subprocess.check_output([str(staged), "version"], text=True).splitlines()[0]
        if first_line != "sing-box version " + config["version"]:
            raise SystemExit("Compiler version mismatch")
        expected_stamp["binary_sha256"] = hashlib.sha256(staged.read_bytes()).hexdigest()
        os.replace(staged, binary)
        stamp.write_text(json.dumps(expected_stamp, indent=2) + "\n")
    print("Installed verified official compiler: " + config["version"])


if __name__ == "__main__":
    main()
