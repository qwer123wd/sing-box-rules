import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("builder", Path(__file__).resolve().parents[1] / "scripts/build.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def entries(**fields):
    value = builder.empty_entries()
    for key, items in fields.items():
        value[key] = set(items)
    return value


def source(**fields):
    return json.dumps({"version": 5, "rules": [fields]}).encode()


class EntryTests(unittest.TestCase):
    def test_internal_duplicates(self):
        value, info = builder.parse_source(source(domain=["a.test", "a.test"]), "x")
        self.assertEqual(value["domain"], {"a.test"})
        self.assertEqual(info["raw_entries"], 2)
        self.assertEqual(info["unique_entries"], 1)

    def test_cross_source_union_and_subtraction(self):
        data = {"category": entries(domain=["shared.test", "only-category.test"]), "proxy": entries(domain=["shared.test", "only-proxy.test"])}
        union, proxy, removed = builder.merge_entries(data, ["category"], "proxy")
        self.assertEqual(union["domain"], {"shared.test", "only-category.test", "only-proxy.test"})
        self.assertEqual(proxy["domain"], {"only-proxy.test"})
        self.assertEqual(removed["domain"], 1)

    def test_different_fields_are_not_equated(self):
        data = {"category": entries(domain_suffix=["example.test"], domain=["video.example.test"]), "proxy": entries(domain=["example.test"], domain_suffix=["video.example.test"])}
        _, proxy, removed = builder.merge_entries(data, ["category"], "proxy")
        self.assertEqual(proxy["domain"], {"example.test"})
        self.assertEqual(proxy["domain_suffix"], {"video.example.test"})
        self.assertEqual(sum(removed.values()), 0)

    def test_case_dot_keywords_and_regex_remain_verbatim(self):
        payload = {"domain": ["A.test", "a.test"], "domain_suffix": [".example.test", "example.test"], "domain_keyword": ["git", "Git"], "domain_regex": ["^www\\.example\\.test$"]}
        value, _ = builder.parse_source(source(**payload), "x")
        for key, items in payload.items():
            self.assertEqual(value[key], set(items))

    def test_serialization_is_deterministic(self):
        first, _ = builder.parse_source(source(domain=["z.test", "a.test", "z.test"]), "a")
        second, _ = builder.parse_source(source(domain=["a.test", "z.test"]), "b")
        self.assertEqual(builder.encode_entries(first), builder.encode_entries(second))
        self.assertEqual(json.loads(builder.encode_entries(first))["version"], 2)

    def test_all_equals_categories_plus_trimmed_proxy(self):
        data = {"one": entries(domain_suffix=["a.test"]), "two": entries(domain=["b.test"]), "proxy": entries(domain_suffix=["a.test", "c.test"], domain=["b.test", "d.test"])}
        union, proxy, _ = builder.merge_entries(data, ["one", "two"], "proxy")
        for field in builder.FIELDS:
            self.assertEqual(union[field], proxy[field] | data["one"][field] | data["two"][field])

    def test_multiple_flat_rules_are_or_merged(self):
        raw = json.dumps({"version": 2, "rules": [{"domain": ["a.test"]}, {"domain_suffix": ["b.test"]}]}).encode()
        value, _ = builder.parse_source(raw, "x")
        self.assertEqual(value["domain"], {"a.test"})
        self.assertEqual(value["domain_suffix"], {"b.test"})

    def test_unsupported_rules_fail_closed(self):
        for rule in ({"type": "logical", "mode": "or", "rules": []}, {"domain": ["a.test"], "invert": True}, {"ip_cidr": ["192.0.2.0/24"]}, {"domain": ["a.test"], "port": [443]}, {"package_name_regex": [".*"]}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                builder.parse_source(json.dumps({"version": 5, "rules": [rule]}).encode(), "x")

    def test_invalid_versions(self):
        for version in (0, 6, True, "5", None):
            with self.subTest(version=version), self.assertRaises(ValueError):
                builder.parse_source(json.dumps({"version": version, "rules": [{"domain": ["a.test"]}]}).encode(), "x")

    def test_empty_or_malformed_input(self):
        for value in (b"<html>Error</html>", b"[]", b"{}", b'{"version":5,"rules":[]}', source(domain=[]), source(domain="a.test"), source(domain=[" a.test"]), source(domain=[42])):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                builder.parse_source(value, "x")

    def test_wrong_source_mapping(self):
        for data, categories, proxy in (({"a": entries()}, ["a"], "a"), ({"a": entries(), "p": entries()}, ["a", "a"], "p"), ({"a": entries(), "p": entries(), "extra": entries()}, ["a"], "p")):
            with self.assertRaises(ValueError):
                builder.merge_entries(data, categories, proxy)

    def test_large_source_drop_requires_manual_override(self):
        previous = {"sources": {"a": {"unique_entries": 100}}}
        with self.assertRaises(ValueError):
            builder.check_source_drop({"a": {"unique_entries": 59}}, previous)
        builder.check_source_drop({"a": {"unique_entries": 60}}, previous)
        builder.check_source_drop({"a": {"unique_entries": 1}}, previous, True)

    def test_new_source_has_no_false_drop(self):
        builder.check_source_drop({"a": {"unique_entries": 1}}, {})

    def test_download_url_restrictions(self):
        for url in ("http://raw.githubusercontent.com/a/b/c/d.json", "https://example.invalid/a.json", "https://token@raw.githubusercontent.com/a/b/c/d.json", "https://raw.githubusercontent.com/a/b/c/d.json?secret=x"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                builder.fetch_source({"tag": "x", "url": url})

    def test_compile_failure_preserves_existing_outputs(self):
        config = {"categories": ["a"], "proxy": "p", "sources": [{"tag": "a"}, {"tag": "p"}]}
        data = [("a", entries(domain=["a.test"]), {"unique_entries": 1}), ("p", entries(domain=["p.test"]), {"unique_entries": 1})]
        version = json.loads((builder.ROOT / "config/compiler.json").read_text())["version"]
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder)
            baseline = {name: ("old-" + name).encode() for name in ("all.json", "all.srs", "proxy.json", "proxy.srs", "SHA256SUMS")}
            for name, raw in baseline.items():
                (out / name).write_bytes(raw)
            with mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version + "\n"), mock.patch.object(builder, "fetch_source", side_effect=lambda item: next(row for row in data if row[0] == item["tag"])), mock.patch.object(builder, "compile_and_validate", side_effect=RuntimeError("compiler failure")):
                with self.assertRaises(RuntimeError):
                    builder.build(config, out / "compiler", out)
            for name, raw in baseline.items():
                self.assertEqual((out / name).read_bytes(), raw)
            self.assertFalse((out / "build-info.json").exists())

    def test_local_telegram_input_does_not_use_network(self):
        raw = source(domain_suffix=["t.test"])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "telegram.json").write_bytes(raw)
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder, "download_public", side_effect=AssertionError("Unexpected download")):
                tag, value, info = builder.fetch_source({"tag": "telegram", "path": "telegram.json"})
            self.assertEqual(tag, "telegram")
            self.assertEqual(value["domain_suffix"], {"t.test"})
            self.assertEqual(info["path"], "telegram.json")
            self.assertNotIn("url", info)
            self.assertEqual((root / "telegram.json").read_bytes(), raw)

    def test_fixed_files_reject_path_traversal_and_generated_output_collision(self):
        for names in (["../ads.srs"], ["all.srs"], ["proxy.json"], ["build-info.json"], ["README.md"], ["ads.srs", "ads.srs"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                builder.fixed_file_info(names)

    def test_ambiguous_or_missing_source_location_is_rejected(self):
        for specification in ({"tag": "x"}, {"tag": "x", "path": "telegram.json", "url": "https://example.invalid/x.json"}):
            with self.assertRaises(ValueError):
                builder.fetch_source(specification)

    def test_build_never_rewrites_fixed_files(self):
        config = {"categories": ["a"], "proxy": "p", "fixed_files": ["telegram.json", "ads.srs"], "sources": [{"tag": "a", "path": "telegram.json"}, {"tag": "p", "url": "https://raw.githubusercontent.com/example/rules/main/p.json"}]}
        version = json.loads((builder.ROOT / "config/compiler.json").read_text())["version"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config").mkdir()
            (root / "config/compiler.json").write_text(json.dumps({"version": version}))
            fixed = {"telegram.json": source(domain=["a.test"]), "ads.srs": b"SRS\x02fixed-original"}
            for name, raw in fixed.items():
                (root / name).write_bytes(raw)
            modified_times = {name: (root / name).stat().st_mtime_ns for name in fixed}

            def fake_compile(compiler, source, target, scratch):
                target.write_bytes(b"SRS\x02test-output")

            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version + "\n"), mock.patch.object(builder, "download_public", return_value=source(domain=["p.test"])), mock.patch.object(builder, "compile_and_validate", side_effect=fake_compile):
                manifest = builder.build(config, root / "compiler", root / "output")
            for name, raw in fixed.items():
                self.assertEqual((root / name).read_bytes(), raw)
                self.assertEqual((root / name).stat().st_mtime_ns, modified_times[name])
                self.assertFalse((root / "output" / name).exists())
            self.assertEqual(set(manifest["fixed_files"]), set(fixed))
            self.assertNotIn("ads.srs", (root / "output/SHA256SUMS").read_text())


if __name__ == "__main__":
    unittest.main()
