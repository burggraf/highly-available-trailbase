import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import surface_closure


MANIFEST = Path(__file__).with_name("surface_manifest.json")


def synthetic_fixture(tmp: Path):
    manifest = copy.deepcopy(surface_closure.load_manifest(MANIFEST))
    root = tmp / "trailbase"
    provenance = tmp / "manifest.json"
    requirements = {}
    for entry in manifest["source_files"]:
        requirements.setdefault(entry["file"], set()).update(a["line"] for a in entry["anchors"])
    for route in manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]:
        requirements.setdefault(route["source"]["file"], set()).add(route["source"]["line"])
    for index, entry in enumerate(manifest["source_files"]):
        name = entry["file"]
        lines = [f"// synthetic {name} line {line}" for line in range(1, max(requirements[name]) + 1)]
        for anchor_index, anchor in enumerate(entry["anchors"]):
            audited = [spec for spec in surface_closure.REQUIRED_NON_ROUTE.values() if spec[1] == name and spec[2] == anchor["line"]]
            token = audited[0][3] if audited else f"synthetic inventory {index} {anchor_index}"
            lines[anchor["line"] - 1] += f" {token}"
            anchor["contains"] = token
        data = ("\n".join(lines) + "\n").encode("utf-8")
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    for route_index, route in enumerate(manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]):
        source = route["source"]
        token = f"synthetic route {route_index} {route['path']}"
        path = root / source["file"]
        data = path.read_text().splitlines()
        data[source["line"] - 1] += f" {token}"
        path.write_text("\n".join(data) + "\n")
        source["contains"] = token
        anchors = next(e for e in manifest["source_files"] if e["file"] == source["file"])["anchors"]
        audited_lines = {spec[2] for spec in surface_closure.REQUIRED_NON_ROUTE.values() if spec[1] == source["file"]}
        if source["line"] in audited_lines:
            anchors.append({"line": source["line"], "contains": token})
        else:
            for anchor in anchors:
                if anchor["line"] == source["line"]:
                    anchor["contains"] = token
    for entry in manifest["source_files"]:
        digest = hashlib.sha256((root / entry["file"]).read_bytes()).hexdigest()
        entry["sha256"] = digest
        for route in manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]:
            if route["source"]["file"] == entry["file"]:
                route["source"]["sha256"] = digest
        for capability in manifest["capabilities"]:
            source = capability["source"]
            if source["file"] == entry["file"]:
                source["sha256"] = digest
                source["contains"] = next(a["contains"] for a in entry["anchors"] if a["line"] == source["line"])
    for route in manifest["routes"] + manifest["debug_only_routes"]:
        node = next(c for c in manifest["capabilities"] if c["name"] == f"route:{route['method']} {route['path']}")
        node["source"] = copy.deepcopy(route["source"])
    recorded = {"sources": [
        {"name": "trailbase", "repo": "trailbaseio/trailbase", "tag": "v0.33.11", "commit": surface_closure.COMMIT,
         "url": "https://codeload.github.com/trailbaseio/trailbase/tar.gz/f24291b894bb6c6696608e5f4c2f68666fe97686",
         "archive_sha256": "78f694531b28e6f8eb7f600a6c4c63f37437b5e965a1a0a357c19dd5780fd852", "regular_files": 1, "expanded_bytes": 1},
        {"name": "litestream", "repo": "benbjohnson/litestream", "tag": "v0.5.17", "commit": surface_closure.LITESTREAM[3],
         "url": "https://codeload.github.com/benbjohnson/litestream/tar.gz/ccd326c175b583b5e82893a6078f06dcef5fba3f",
         "archive_sha256": "cbfb487c66690679234ec46e28d03a2de60b795b7b4466f3444755fc4d39e7d8", "regular_files": 1, "expanded_bytes": 1},
    ]}
    data = (json.dumps(recorded, sort_keys=True, separators=(",", ":")) + "\n").encode()
    provenance.write_bytes(data)
    manifest["source"]["root"] = root.name
    manifest["source"]["provenance"]["file"] = provenance.name
    manifest["source"]["provenance"]["sha256"] = hashlib.sha256(data).hexdigest()
    return manifest, root, provenance


class SurfaceManifestTests(unittest.TestCase):
    def test_source_artifact_mismatches_are_infeasible(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            surface_closure.verify_source(root, provenance, manifest)
            for entry in manifest["source_files"]:
                path = root / entry["file"]
                original = path.read_bytes()
                with self.subTest(tamper=entry["file"]):
                    path.write_bytes(original + b"tampered")
                    with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)
                    path.write_bytes(original)
            for entry in manifest["source_files"]:
                path = root / entry["file"]
                original = path.read_bytes(); path.unlink()
                with self.subTest(delete=entry["file"]):
                    with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)
                path.write_bytes(original)
            extra = root / surface_closure.SOURCE_SCOPES[0] / "extra.rs"
            extra.write_text("// extra\n")
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)
            extra.unlink()
            broken = copy.deepcopy(manifest); broken["routes"][0]["source"]["sha256"] = "0" * 64
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, broken)
            broken = copy.deepcopy(manifest); broken["source_files"][0]["anchors"][0]["contains"] = "missing"
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, broken)
            broken = copy.deepcopy(manifest); broken["routes"][0]["source"]["contains"] = "missing"
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, broken)

            mutations = [
                ("missing provenance", lambda m, p: p.unlink()),
                ("invalid utf8", lambda m, p: p.write_bytes(b"\\xff")),
                ("wrong digest", lambda m, p: m["source"]["provenance"].update(sha256="0" * 64)),
                ("duplicate TrailBase", lambda m, p: json.loads(p.read_text())["sources"].append(json.loads(p.read_text())["sources"][0])),
                ("extra source", lambda m, p: json.loads(p.read_text())["sources"].append({})),
            ]
            for label, mutate in mutations:
                with self.subTest(provenance=label):
                    m = copy.deepcopy(manifest); q = tmp / f"{label.replace(' ', '_')}.json"; q.write_bytes(provenance.read_bytes())
                    if label in {"duplicate TrailBase", "extra source"}:
                        record = json.loads(q.read_text()); record["sources"].append(record["sources"][0] if label.startswith("duplicate") else {}); q.write_text(json.dumps(record))
                    else: mutate(m, q)
                    with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, q, m)
            for key in ("tag", "commit", "repo", "name", "url", "archive_sha256", "regular_files", "expanded_bytes"):
                with self.subTest(provenance_key=key):
                    record = json.loads(provenance.read_text()); value = record["sources"][0][key]; record["sources"][0][key] = "bad" if isinstance(value, str) else 0
                    q = tmp / f"bad_{key}.json"; q.write_text(json.dumps(record)); m = copy.deepcopy(manifest); m["source"]["provenance"]["sha256"] = hashlib.sha256(q.read_bytes()).hexdigest()
                    with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, q, m)
            for key_change in ("missing key", "extra key", "wrong sources type"):
                with self.subTest(provenance_keys=key_change):
                    record = json.loads(provenance.read_text())
                    if key_change == "missing key": record["sources"][0].pop("repo")
                    elif key_change == "extra key": record["sources"][0]["extra"] = True
                    else: record["sources"] = "not an array"
                    q = tmp / f"bad_{key_change.replace(' ', '_')}.json"; q.write_text(json.dumps(record)); m = copy.deepcopy(manifest); m["source"]["provenance"]["sha256"] = hashlib.sha256(q.read_bytes()).hexdigest()
                    with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, q, m)

            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(tmp / "missing-trailbase", provenance, manifest)
            not_dir = tmp / "not-dir"; not_dir.write_text("x")
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(not_dir, provenance, manifest)
            with mock.patch.object(Path, "rglob", side_effect=RuntimeError("boom")):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)

    def test_graph_is_one_to_one_and_reachable(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        caps = manifest["capabilities"]
        self.assertEqual(len({c["name"] for c in caps}), len(caps))
        self.assertEqual(set(manifest["graph_accounting"]), set(surface_closure.EXPECTED_ACCOUNTING))
        self.assertEqual(manifest["graph_accounting"]["providers"], surface_closure.EXPECTED_ACCOUNTING["providers"])


class SurfaceClosureTests(unittest.TestCase):
    def test_manifest_is_pinned_and_complete(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        self.assertEqual(len(manifest["routes"]), 82)
        self.assertEqual(manifest["source"]["commit"], surface_closure.COMMIT)

    def test_source_audited_non_route_inventory_is_exact(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        expected = {
            "router:server", "router:records", "router:transaction", "router:auth", "router:oauth",
            "router:admin", "router:admin-auth", "router:wasm", "router:custom",
            "conditional:transactions-enabled", "conditional:records-subscribe-sqlite", "conditional:auth-anonymous-signin",
            "conditional:auth-otp-signin", "conditional:wasm-feature", "conditional:independent-admin-listener",
            "conditional:public-dir", "conditional:public-dir-spa", "conditional:auth-rate-limit",
            "job:Backup", "job:Heartbeat", "job:LogCleaner", "job:AuthCleaner", "job:QueryOptimizer", "job:FileDeletions",
            "dynamic:wasm-manifest", "dynamic:custom-router", "listener:main", "listener:admin",
            "writer:main-db", "writer:session-db", "writer:logs-db", "writer:sql-query", "writer:ddl",
            "writer:config", "writer:backup", "writer:restore", "writer:filesystem", "writer:object-store", "writer:wasm",
            "provider:email-smtp", "provider:email-sendmail", "provider:oauth-oidc", "provider:oauth-apple",
            "provider:oauth-discord", "provider:oauth-gitlab", "provider:oauth-github", "provider:oauth-google",
            "provider:oauth-facebook", "provider:oauth-microsoft", "provider:oauth-twitch", "provider:oauth-yandex",
            "telemetry:logs",
        }
        non_routes = {c["name"] for c in manifest["capabilities"] if c["class"] != "route"}
        self.assertEqual(non_routes, expected)
    def test_valid_synthetic_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, root, provenance = synthetic_fixture(Path(td))
            surface_closure.verify_source(root, provenance, manifest)

    def test_exact_route_identity_and_conditions(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        routes = {(r["method"], r["path"]): r for r in manifest["routes"]}
        self.assertEqual(len(routes), 82)
        self.assertEqual(routes[("DELETE", "/api/auth/v1/delete")]["condition"], "always")
        self.assertEqual(routes[("GET", "/api/healthcheck")]["handler"], "healthcheck_handler")
        self.assertEqual(manifest["debug_only_routes"][0]["condition"], "cfg(debug_assertions)")

    def test_exact_debug_and_listener_instances(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        self.assertEqual([(x["method"], x["path"], x["handler"]) for x in manifest["debug_only_routes"]], [("GET", "/api/whoami", "whoami_handler")])
        self.assertEqual({(x["method"], x["path"], x["handler"]) for x in manifest["listener_route_instances"]}, {
            ("POST", "/api/auth/v1/login", "login_handler"),
            ("GET", "/api/auth/v1/status", "login_status_handler"),
            ("GET", "/api/auth/v1/logout", "logout_handler"),
        })

    def test_exact_rules_and_binding(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        self.assertEqual(surface_closure.bind_request("POST", "/api/records/v1/main_ops", manifest), "main")
        self.assertEqual(surface_closure.bind_request("POST", "/api/records/v1/aux_ops", manifest), "aux")
        self.assertEqual(surface_closure.bind_request("POST", "/api/auth/v1/logout", manifest), "session")
        self.assertIsNone(surface_closure.bind_request("POST", "/api/records/v1/other", manifest))

    def test_top_level_and_nested_schema_rejections(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        for key in surface_closure.TOP_LEVEL:
            with self.subTest(missing=key):
                broken = copy.deepcopy(manifest); broken.pop(key)
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)
            with self.subTest(extra=key):
                broken = copy.deepcopy(manifest); broken["extra"] = True
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)
        mutations = [("source", "name", 1), ("source_files", 0, None), ("routes", 0, "method"), ("capabilities", 0, "source"), ("graph_accounting", "routers", None)]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key):
                broken = copy.deepcopy(manifest)
                if section == "source": broken[section][key] = value
                elif section == "source_files": broken[section][key]["anchors"] = "bad"
                elif section == "routes": broken[section][key] = value
                elif section == "capabilities": broken[section][key] = value
                else: broken[section][key] = "bad"
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)

    def test_unsafe_and_out_of_scope_paths_rejected(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        for bad in ("/absolute", "", ".", "..", "a/../b", "a\\b", "outside/file.rs"):
            with self.subTest(path=bad):
                broken = copy.deepcopy(manifest); broken["source"]["root"] = bad
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)
            with self.subTest(provenance=bad):
                broken = copy.deepcopy(manifest); broken["source"]["provenance"]["file"] = bad
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)
        for bad in ("/x.rs", "../x.rs", "outside/x.rs"):
            broken = copy.deepcopy(manifest); broken["source_files"][0]["file"] = bad
            with self.subTest(source_file=bad):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(broken)

    def test_every_tagged_source_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            base, root, provenance = synthetic_fixture(Path(td))
            tagged = [("route", r["source"]) for r in base["routes"]]
            tagged += [("debug", r["source"]) for r in base["debug_only_routes"]]
            tagged += [("listener", r["source"]) for r in base["listener_route_instances"]]
            tagged += [(c["name"], c["source"]) for c in base["capabilities"]]
            for label, field in (("digest", "sha256"), ("line", "line"), ("contains", "contains")):
                for name, source in tagged:
                    with self.subTest(kind=label, name=name):
                        broken = copy.deepcopy(base)
                        target = next((r["source"] for r in broken["routes"] if r["source"] == source), None)
                        if target is None: target = next((r["source"] for r in broken["debug_only_routes"] + broken["listener_route_instances"] if r["source"] == source), None)
                        if target is None: target = next(c["source"] for c in broken["capabilities"] if c["name"] == name)
                        target[field] = "0" * 64 if field == "sha256" else target[field] + (1 if field == "line" else "missing")
                        with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, broken)

    def test_filesystem_exception_is_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, root, provenance = synthetic_fixture(Path(td))
            with mock.patch.object(Path, "stat", side_effect=OSError("boom")):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)

if __name__ == "__main__":
    unittest.main()
