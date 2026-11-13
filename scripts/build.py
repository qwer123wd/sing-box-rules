#!/usr/bin/env python3
"""Exact, type-aware domain-entry union and subtraction; fail closed on new syntax."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("domain", "domain_suffix", "domain_keyword", "domain_regex")
MAX_SOURCE_BYTES = 8 * 1024 * 1024


def empty_entries():
    return {field: set() for field in FIELDS}


def count_entries(entries):
    return sum(len(values) for values in entries.values())


def parse_source(raw, tag):
    document = json.loads(raw)
    if not isinstance(document, dict) or type(document.get("version")) is not int or document["version"] not in range(1, 6):
        raise ValueError(tag + ": unsupported rule-set version")
    rules = document.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError(tag + ": missing/non-list/empty rules")
    entries = empty_entries()
    raw_count = 0
    for rule in rules:
        if not isinstance(rule, dict) or not rule or set(rule) - set(FIELDS):
            raise ValueError(tag + ": new/unsupported rule fields; refusing to flatten logical or conditional rules")
        for field, values in rule.items():
            if not isinstance(values, list) or any(not isinstance(value, str) or not value or value != value.strip() for value in values):
                raise ValueError(tag + ": invalid " + field)
            raw_count += len(values)
            entries[field].update(values)
    if not count_entries(entries):
        raise ValueError(tag + ": all rule entries are empty")
    return entries, {"version": document["version"], "raw_entries": raw_count, "unique_entries": count_entries(entries), "fields": {k: len(v) for k, v in entries.items() if v}}


def merge_entries(sources, categories, proxy_tag):
    if len(set(categories)) != len(categories) or proxy_tag in categories or set(sources) != set(categories) | {proxy_tag}:
        raise ValueError("Expected exactly the configured five category sources and original proxy")
    category_union = empty_entries()
    for tag in categories:
        for field in FIELDS:
            category_union[field].update(sources[tag][field])
    original = sources[proxy_tag]
    all_entries = {field: original[field] | category_union[field] for field in FIELDS}
    proxy_entries = {field: original[field] - category_union[field] for field in FIELDS}
    removed = {field: len(original[field] & category_union[field]) for field in FIELDS}
    # These assertions express the user's exact entry-level contract, not semantic DNS equivalence.
    for field in FIELDS:
        assert not (proxy_entries[field] & category_union[field])
        assert (proxy_entries[field] | category_union[field]) == all_entries[field]
    return all_entries, proxy_entries, removed


def encode_entries(entries):
    # All accepted fields exist in v2; emit v2 rather than inheriting unrelated upstream v5 features.
    fields = {field: sorted(entries[field]) for field in FIELDS if entries[field]}
    return (json.dumps({"version": 2, "rules": [fields] if fields else []}, ensure_ascii=False, indent=2) + "\n").encode()


def download_public(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "raw.githubusercontent.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Only configured public GitHub HTTPS sources are allowed")
    result = subprocess.run([
        "curl", "--fail", "--location", "--silent", "--show-error",
        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
        "--retry", "2", "--connect-timeout", "15", "--max-time", "60",
        "--max-filesize", str(MAX_SOURCE_BYTES), url,
    ], capture_output=True, check=True)
    raw = result.stdout
    if len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("Source too large")
    return raw


def fetch_source(source):
    if ("url" in source) == ("path" in source):
        raise ValueError("Specify exactly one source URL or repository path")
    if "path" in source:
        if not source["path"].endswith(".json"):
            raise ValueError("Local source must be JSON")
        raw = read_fixed_file(source["path"])
        location = {"path": source["path"]}
    else:
        raw = download_public(source["url"])
        location = {"url": source["url"]}
    entries, info = parse_source(raw, source["tag"])
    info.update(location)
    info["sha256"] = hashlib.sha256(raw).hexdigest()
    return source["tag"], entries, info


def read_fixed_file(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]+\.(json|srs)", name) or name in ("all.json", "all.srs", "proxy.json", "proxy.srs", "build-info.json"):
        raise ValueError("Invalid/colliding fixed repository filename")
    path = (ROOT / name).resolve()
    if path.parent != ROOT.resolve():
        raise ValueError("Fixed file must stay inside the repository")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_SOURCE_BYTES:
        raise ValueError("Empty/oversized fixed repository file: " + name)
    return raw


def fixed_file_info(names):
    if len(names) != len(set(names)):
        raise ValueError("Duplicate fixed repository filename")
    result = {}
    for name in names:
        raw = read_fixed_file(name)
        result[name] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
    return result


def check_source_drop(current, previous, allow_large_drop=False):
    if allow_large_drop:
        return
    for tag, info in current.items():
        old = previous.get("sources", {}).get(tag, {}).get("unique_entries", 0)
        if old and info["unique_entries"] < old * 0.6:
            raise ValueError(tag + ": more than 40% of entries disappeared; review upstream before allowing a large drop")


def compile_and_validate(compiler, source, target, scratch):
    subprocess.run([str(compiler), "rule-set", "compile", "--output", str(target), str(source)], check=True, capture_output=True)
    if target.stat().st_size < 8 or target.read_bytes()[:3] != b"SRS":
        raise ValueError("Invalid compiled binary: " + target.name)
    decoded = scratch / (target.stem + "-roundtrip.json")
    subprocess.run([str(compiler), "rule-set", "decompile", "--output", str(decoded), str(target)], check=True, capture_output=True)
    document = json.loads(decoded.read_bytes())
    if not isinstance(document.get("rules"), list) or not document["rules"]:
        raise ValueError("Empty/invalid decoded rule-set: " + target.name)


def build(config, compiler, destination, allow_large_drop=False):
    compiler = Path(compiler).resolve()
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    expected_version = json.loads((ROOT / "config/compiler.json").read_text())["version"]
    version_line = subprocess.check_output([str(compiler), "version"], text=True).splitlines()[0]
    if version_line != "sing-box version " + expected_version:
        raise ValueError("Use the checksum-pinned compiler from scripts/install_compiler.py")
    specifications = config["sources"]
    if len({item["tag"] for item in specifications}) != len(specifications):
        raise ValueError("Duplicate input source tag")
    fixed_files = fixed_file_info(config.get("fixed_files", []))
    if any(source.get("path") not in fixed_files for source in specifications if "path" in source):
        raise ValueError("Local merge inputs must be listed as fixed files")
    with ThreadPoolExecutor(max_workers=6) as pool:
        downloaded = list(pool.map(fetch_source, specifications))
    sources = {tag: entries for tag, entries, _ in downloaded}
    source_info = {tag: info for tag, _, info in downloaded}
    manifest_path = destination / "build-info.json"
    previous = json.loads(manifest_path.read_text()) if manifest_path.is_file() else {}
    check_source_drop(source_info, previous, allow_large_drop)
    all_entries, proxy_entries, removed = merge_entries(sources, config["categories"], config["proxy"])
    if not count_entries(all_entries) or not count_entries(proxy_entries):
        raise ValueError("Unexpected empty output; preserving previous published rules")
    manifest = {
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "deduplication": "exact string equality within the same rule field; no cross-field or semantic subtraction",
        "source_format_version": 2,
        "compiler": expected_version,
        "sources": source_info,
        "fixed_files": fixed_files,
        "outputs": {},
        "proxy_removed_by_field": {k: v for k, v in removed.items() if v},
        "proxy_removed_total": sum(removed.values()),
    }
    with tempfile.TemporaryDirectory(prefix=".build-", dir=destination) as folder:
        stage = Path(folder)
        for tag, entries in (("all", all_entries), ("proxy", proxy_entries)):
            source = stage / (tag + ".json")
            target = stage / (tag + ".srs")
            source.write_bytes(encode_entries(entries))
            compile_and_validate(compiler, source, target, stage)
            manifest["outputs"][tag] = {
                "entries": count_entries(entries),
                "fields": {k: len(v) for k, v in entries.items() if v},
                "files": {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size} for path in (source, target)},
            }
        names = ["all.json", "all.srs", "proxy.json", "proxy.srs"]
        checksums = "".join(hashlib.sha256((stage / name).read_bytes()).hexdigest() + "  " + name + "\n" for name in names)
        (stage / "SHA256SUMS").write_text(checksums)
        (stage / "build-info.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
        # No output is touched until both binaries and both round trips pass. Git publication is one commit.
        for name in names + ["SHA256SUMS", "build-info.json"]:
            os.replace(stage / name, destination / name)
    print(json.dumps({"all_entries": count_entries(all_entries), "proxy_entries": count_entries(proxy_entries), "proxy_removed": sum(removed.values())}))
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, default=ROOT / ".tools/sing-box")
    parser.add_argument("--output", type=Path, default=ROOT)
    parser.add_argument("--allow-large-drop", action="store_true")
    args = parser.parse_args()
    build(json.loads((ROOT / "config/sources.json").read_text()), args.sing_box, args.output, args.allow_large_drop)


if __name__ == "__main__":
    main()
