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
            baseline = {name: ("old-" + name).encode() for name in ("data/all.json", "data/all.srs", "data/proxy.json", "data/proxy.srs", "SHA256SUMS")}
            for name, raw in baseline.items():
                (out / name).parent.mkdir(parents=True, exist_ok=True)
                (out / name).write_bytes(raw)
            with mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version + "\n"), mock.patch.object(builder, "fetch_source", side_effect=lambda item, cache=None: next(row for row in data if row[0] == item["tag"])), mock.patch.object(builder, "compile_and_validate", side_effect=RuntimeError("compiler failure")):
                with self.assertRaises(RuntimeError):
                    builder.build(config, out / "compiler", out)
            for name, raw in baseline.items():
                self.assertEqual((out / name).read_bytes(), raw)
            self.assertFalse((out / "build-info.json").exists())

    def test_local_telegram_input_does_not_use_network(self):
        raw = source(domain_suffix=["t.test"])
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "data").mkdir()
            (root / "data/telegram.json").write_bytes(raw)
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder, "download_public", side_effect=AssertionError("Unexpected download")):
                tag, value, info = builder.fetch_source({"tag": "telegram", "path": "data/telegram.json"})
            self.assertEqual(tag, "telegram")
            self.assertEqual(value["domain_suffix"], {"t.test"})
            self.assertEqual(info["path"], "data/telegram.json")
            self.assertNotIn("url", info)
            self.assertEqual((root / "data/telegram.json").read_bytes(), raw)

    def test_fixed_files_reject_path_traversal_and_generated_output_collision(self):
        for names in (["../ads.srs"], ["data/../ads.srs"], ["data/all.srs"], ["data/proxy.json"], ["data/build-info.json"], ["README.md"], ["data/ads.srs", "data/ads.srs"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                builder.fixed_file_info(names)

    def test_ambiguous_or_missing_source_location_is_rejected(self):
        for specification in ({"tag": "x"}, {"tag": "x", "path": "telegram.json", "url": "https://example.invalid/x.json"}):
            with self.assertRaises(ValueError):
                builder.fetch_source(specification)

    def test_build_never_rewrites_fixed_files(self):
        config = {"categories": ["a"], "proxy": "p", "fixed_files": ["data/telegram.json", "data/ads.srs", "data/ui.zip"], "sources": [{"tag": "a", "path": "data/telegram.json"}, {"tag": "p", "url": "https://raw.githubusercontent.com/example/rules/main/p.json"}]}
        version = json.loads((builder.ROOT / "config/compiler.json").read_text())["version"]
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "config").mkdir()
            (root / "data").mkdir()
            (root / "config/compiler.json").write_text(json.dumps({"version": version}))
            fixed = {"data/telegram.json": source(domain=["a.test"]), "data/ads.srs": b"SRS\x02fixed-original", "data/ui.zip": b"PKfixed-ui"}
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

    def test_ip_mirrors_do_not_expand_merge_input_syntax(self):
        raw = source(ip_cidr=["192.0.2.0/24", "2001:db8::/32"])
        value, info = builder.parse_source(raw, "ip", allow_ip=True)
        self.assertEqual(info["unique_entries"], 2)
        self.assertEqual(len(value["ip_cidr"]), 2)
        with self.assertRaises(ValueError):
            builder.parse_source(raw, "ip")
        with self.assertRaises(ValueError):
            builder.parse_source(source(ip_cidr=["invalid"]), "ip", allow_ip=True)

    def test_mirror_paths_and_fixed_file_collisions_are_rejected(self):
        for tags in (["../escape"], ["all"], ["proxy"], ["a", "a"], ["telegram"]):
            config = {"sources": [], "fixed_files": ["data/telegram.json"], "mirrors": [{"tag": tag, "json_url": "j", "srs_url": "s"} for tag in tags]}
            with self.subTest(tags=tags), self.assertRaises(ValueError):
                builder.mirror_output_names(config)

    def test_shared_mirror_and_merge_json_url_must_agree(self):
        config = {"sources": [{"tag": "a", "url": "one"}], "mirrors": [{"tag": "a", "json_url": "two", "srs_url": "s"}]}
        with self.assertRaises(ValueError):
            builder.mirror_output_names(config)

    def test_mirror_pair_rejects_semantic_difference(self):
        with mock.patch.object(builder, "compile_and_validate", return_value={"rules": [{"domain": ["a.test"]}]}), mock.patch.object(builder, "decode_and_validate", return_value={"rules": [{"domain": ["b.test"]}]}):
            with self.assertRaises(ValueError):
                builder.validate_mirror_pair(Path("compiler"), Path("a.json"), Path("a.srs"), Path("scratch"))

    def test_mirror_pair_accepts_reordered_fields_without_rewriting(self):
        with mock.patch.object(builder, "compile_and_validate", return_value={"rules": [{"domain": ["a.test", "b.test"]}]}), mock.patch.object(builder, "decode_and_validate", return_value={"rules": [{"domain": ["b.test", "a.test"]}]}):
            builder.validate_mirror_pair(Path("compiler"), Path("a.json"), Path("a.srs"), Path("scratch"))

    def mirror_fixture(self, root):
        (root / "config").mkdir()
        version = json.loads((builder.ROOT / "config/compiler.json").read_text())["version"]
        (root / "config/compiler.json").write_text(json.dumps({"version": version}))
        base = "https://raw.githubusercontent.com/example/rules/main/"
        config = {"categories": ["a"], "proxy": "p", "sources": [{"tag": "a", "url": base + "a.json"}, {"tag": "p", "url": base + "p.json"}], "mirrors": [{"tag": tag, "json_url": base + tag + ".json", "srs_url": base + tag + ".srs"} for tag in ("a", "extra")]}
        raw = {base + "a.json": source(domain=["a.test"]), base + "p.json": source(domain=["p.test"]), base + "extra.json": source(ip_cidr=["192.0.2.0/24"]), base + "a.srs": b"SRS\x05upstream-a", base + "extra.srs": b"SRS\x05upstream-extra"}
        return config, raw, version

    def test_independent_mirrors_are_verbatim_and_download_shared_json_once(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config, payloads, version = self.mirror_fixture(root)
            def compile_fake(compiler, source, binary, scratch):
                binary.write_bytes(b"SRS\x02generated")
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version), mock.patch.object(builder, "download_public", side_effect=payloads.__getitem__) as download, mock.patch.object(builder, "compile_and_validate", side_effect=compile_fake), mock.patch.object(builder, "validate_mirror_pair"):
                manifest = builder.build(config, root / "compiler", root)
            self.assertEqual(download.call_count, len(payloads))
            for item in config["mirrors"]:
                for suffix, key in ((".json", "json_url"), (".srs", "srs_url")):
                    self.assertEqual((root / "data" / (item["tag"] + suffix)).read_bytes(), payloads[item[key]])
            self.assertEqual(manifest["outputs"]["all"]["entries"], 2)
            self.assertNotIn("ip_cidr", json.loads((root / "data/all.json").read_text())["rules"][0])
            self.assertEqual(set(manifest["sources"]), {"a", "p"})
            self.assertEqual(set(manifest["mirrors"]), {"a", "extra"})
            self.assertFalse((root / "all.json").exists())

    def test_mirror_failure_preserves_entire_previous_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config, payloads, version = self.mirror_fixture(root)
            names = ["data/all.json", "data/all.srs", "data/proxy.json", "data/proxy.srs"] + builder.mirror_output_names(config) + ["SHA256SUMS"]
            before = {name: ("previous-" + name).encode() for name in names}
            before["build-info.json"] = b"{}"
            for name, raw in before.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(raw)
            def compile_fake(compiler, source, binary, scratch):
                binary.write_bytes(b"SRS\x02generated")
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version), mock.patch.object(builder, "download_public", side_effect=payloads.__getitem__), mock.patch.object(builder, "compile_and_validate", side_effect=compile_fake), mock.patch.object(builder, "validate_mirror_pair", side_effect=ValueError("mismatched upstream pair")):
                with self.assertRaises(ValueError):
                    builder.build(config, root / "compiler", root)
            for name, raw in before.items():
                self.assertEqual((root / name).read_bytes(), raw)
            self.assertFalse(list(root.glob(".build-*")))

    def test_workflow_publishes_exact_dynamic_whitelist(self):
        import shlex
        config = json.loads((builder.ROOT / "config/sources.json").read_text())
        workflow = (builder.ROOT / ".github/workflows/update-rules.yml").read_text()
        command = workflow.split("          git add ", 1)[1].split("          if git diff", 1)[0].replace("\\\n", " ")
        actual = set(shlex.split(command))
        expected = {"data/all.json", "data/all.srs", "data/proxy.json", "data/proxy.srs", "SHA256SUMS", "build-info.json"} | set(builder.mirror_output_names(config))
        self.assertEqual(actual, expected)
        self.assertFalse(actual & set(config["fixed_files"]))

    def test_download_failure_preserves_previous_manifest_and_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config, _, version = self.mirror_fixture(root)
            (root / "data").mkdir()
            (root / "data/all.srs").write_bytes(b"previous")
            (root / "build-info.json").write_bytes(b"{}")
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version), mock.patch.object(builder, "download_public", side_effect=RuntimeError("download failed")):
                with self.assertRaises(RuntimeError):
                    builder.build(config, root / "compiler", root)
            self.assertEqual((root / "data/all.srs").read_bytes(), b"previous")
            self.assertEqual((root / "build-info.json").read_bytes(), b"{}")

    def test_large_independent_mirror_drop_stops_before_publication(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            config, payloads, version = self.mirror_fixture(root)
            previous = json.dumps({"mirrors": {"extra": {"unique_entries": 100}}}).encode()
            (root / "build-info.json").write_bytes(previous)
            with mock.patch.object(builder, "ROOT", root), mock.patch.object(builder.subprocess, "check_output", return_value="sing-box version " + version), mock.patch.object(builder, "download_public", side_effect=payloads.__getitem__), mock.patch.object(builder, "compile_and_validate") as compile_mock:
                with self.assertRaisesRegex(ValueError, "40%"):
                    builder.build(config, root / "compiler", root)
            compile_mock.assert_not_called()
            self.assertEqual((root / "build-info.json").read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
