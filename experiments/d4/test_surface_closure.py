import copy
from dataclasses import FrozenInstanceError, replace, replace
import hashlib
import json
import os
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
    tagged_sources = [r["source"] for r in manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]]
    tagged_sources += [c["source"] for c in manifest["capabilities"]]
    for entry in manifest["source_files"]:
        name = entry["file"]
        sources = [*entry["anchors"], *(s for s in tagged_sources if s["file"] == name)]
        lines = [f"// synthetic {name} line {line}" for line in range(1, max(s["line"] for s in sources) + 1)]
        for source in sources:
            if source["contains"] not in lines[source["line"] - 1]:
                lines[source["line"] - 1] += f" {source['contains']}"
        data = ("\n".join(lines) + "\n").encode("utf-8")
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        entry["sha256"] = digest
        for source in tagged_sources:
            if source["file"] == name:
                source["sha256"] = digest
    recorded = {"sources": [
        {"name": "trailbase", "repo": "trailbaseio/trailbase", "tag": "v0.33.11", "commit": surface_closure.COMMIT,
         "url": "https://codeload.github.com/trailbaseio/trailbase/tar.gz/f24291b894bb6c6696608e5f4c2f68666fe97686",
         "archive_sha256": "78f694531b28e6f8eb7f600a6c4c63f37437b5e965a1a0a357c19dd5780fd852", "regular_files": 1512, "expanded_bytes": 17610038},
        {"name": "litestream", "repo": "benbjohnson/litestream", "tag": "v0.5.17", "commit": surface_closure.LITESTREAM[3],
         "url": "https://codeload.github.com/benbjohnson/litestream/tar.gz/ccd326c175b583b5e82893a6078f06dcef5fba3f",
         "archive_sha256": "cbfb487c66690679234ec46e28d03a2de60b795b7b4466f3444755fc4d39e7d8", "regular_files": 294, "expanded_bytes": 3796066},
    ]}
    data = (json.dumps(recorded, sort_keys=True, separators=(",", ":")) + "\n").encode()
    provenance.write_bytes(data)
    manifest["source"]["root"] = root.name
    manifest["source"]["provenance"]["file"] = provenance.name
    manifest["source"]["provenance"]["sha256"] = hashlib.sha256(data).hexdigest()
    return manifest, root.resolve(), provenance.resolve()


class SurfaceManifestTests(unittest.TestCase):
    def test_source_artifact_mismatches_are_infeasible(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            with mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest)):
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
                ("invalid utf8", lambda m, p: p.write_bytes(b"\xff")),
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
            with mock.patch.object(Path, "iterdir", side_effect=RuntimeError("boom")):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)

    def test_symlinked_source_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            target = tmp / "trailbase-target"
            root.rename(target)
            root.symlink_to(target, target_is_directory=True)
            with mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest)):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.verify_source(root, provenance, manifest)

    def test_symlinked_descendant_directory_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            directory = root / "crates" / "core"
            target = tmp / "core-target"
            directory.rename(target)
            directory.symlink_to(target, target_is_directory=True)
            with mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest)):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.verify_source(root, provenance, manifest)

    def test_symlinked_provenance_parent_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            real = tmp / "provenance-dir"
            real.mkdir(); provenance.rename(real / provenance.name)
            link_parent = tmp / "linked"
            link_parent.symlink_to(real, target_is_directory=True)
            # The canonical path resolves through the symlink, but the supplied
            # pathname remains a symlinked parent and must not be trusted.
            with mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest)):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.verify_source(root, link_parent / provenance.name, manifest)

    def test_regular_leaf_replacement_after_acquisition_uses_pinned_snapshot(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            expected_count = len(manifest["source_files"])
            target = root / manifest["source_files"][0]["file"]
            replacement = tmp / "replacement.rs"
            replacement.write_bytes(b"// replacement must not be consumed\n")
            real_open, real_fd_bytes = os.open, surface_closure._fd_bytes
            rs_opens = 0

            def tracked_open(path, flags, *args, **kwargs):
                nonlocal rs_opens
                fd = real_open(path, flags, *args, **kwargs)
                if isinstance(path, str) and path.endswith(".rs"):
                    rs_opens += 1
                    if rs_opens == expected_count:
                        os.replace(replacement, target)
                return fd

            def checked_fd_bytes(fd, name, identity=None, max_bytes=None):
                if name != "provenance": self.assertEqual(rs_opens, expected_count)
                return real_fd_bytes(fd, name, identity, max_bytes)

            pin = mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest))
            with pin, mock.patch.object(surface_closure.os, "open", side_effect=tracked_open), mock.patch.object(surface_closure, "_fd_bytes", side_effect=checked_fd_bytes):
                surface_closure.verify_source(root, provenance, manifest)
            self.assertEqual(rs_opens, expected_count)
            self.assertEqual(target.read_bytes(), b"// replacement must not be consumed\n")

    def test_source_inode_identity_is_bound_during_enumeration(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, root, provenance = synthetic_fixture(Path(td))
            expected_count = len(manifest["source_files"])
            real_open, real_fstat, real_fd_bytes = os.open, os.fstat, surface_closure._fd_bytes
            source_fds, identities = set(), {}

            def tracked_open(path, flags, *args, **kwargs):
                fd = real_open(path, flags, *args, **kwargs)
                if isinstance(path, str) and path.endswith(".rs"): source_fds.add(fd)
                return fd

            def tracked_fstat(fd):
                st = real_fstat(fd)
                if fd in source_fds: identities[fd] = (st.st_dev, st.st_ino, st.st_size)
                return st

            def checked_fd_bytes(fd, name, identity=None, max_bytes=None):
                if name != "provenance":
                    self.assertEqual(len(identities), expected_count)
                    self.assertEqual(identity, identities[fd])
                return real_fd_bytes(fd, name, identity, max_bytes)

            pin = mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest))
            with pin, mock.patch.object(surface_closure.os, "open", side_effect=tracked_open), mock.patch.object(surface_closure.os, "fstat", side_effect=tracked_fstat), mock.patch.object(surface_closure, "_fd_bytes", side_effect=checked_fd_bytes):
                surface_closure.verify_source(root, provenance, manifest)

    def test_verify_source_does_not_use_path_reads(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, root, provenance = synthetic_fixture(Path(td))
            pin = mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest))
            with pin, mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Path read")), mock.patch.object(Path, "read_text", side_effect=AssertionError("Path read")):
                surface_closure.verify_source(root, provenance, manifest)

    def test_regular_leaf_replacement_before_acquisition_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            target = root / manifest["source_files"][0]["file"]
            parent_identity = (target.parent.stat().st_dev, target.parent.stat().st_ino)
            replacement = tmp / "replacement.rs"
            replacement.write_bytes(b"// altered before acquisition\n")
            real_open, swapped = os.open, False

            def replacing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                dir_fd = kwargs.get("dir_fd")
                if not swapped and path == target.name and dir_fd is not None:
                    st = os.fstat(dir_fd)
                    if (st.st_dev, st.st_ino) == parent_identity:
                        os.replace(replacement, target)
                        swapped = True
                return real_open(path, flags, *args, **kwargs)

            pin = mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest))
            with pin, mock.patch.object(surface_closure.os, "open", side_effect=replacing_open):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.verify_source(root, provenance, manifest)
            self.assertTrue(swapped)

    def test_regular_leaf_symlink_swap_before_acquisition_fails(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            manifest, root, provenance = synthetic_fixture(tmp)
            target = root / manifest["source_files"][0]["file"]
            parent_identity = (target.parent.stat().st_dev, target.parent.stat().st_ino)
            replacement = tmp / "replacement.rs"
            replacement.write_bytes(target.read_bytes())
            real_open, swapped = os.open, False

            def replacing_open(path, flags, *args, **kwargs):
                nonlocal swapped
                dir_fd = kwargs.get("dir_fd")
                if not swapped and path == target.name and dir_fd is not None:
                    st = os.fstat(dir_fd)
                    if (st.st_dev, st.st_ino) == parent_identity:
                        target.unlink()
                        target.symlink_to(replacement)
                        swapped = True
                return real_open(path, flags, *args, **kwargs)

            pin = mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest))
            with pin, mock.patch.object(surface_closure.os, "open", side_effect=replacing_open):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.verify_source(root, provenance, manifest)
            self.assertTrue(swapped)

    def test_load_manifest_hides_os_error_details(self):
        missing = Path("missing-sensitive-manifest-name.json")
        with self.assertRaises(surface_closure.SurfaceError) as raised:
            surface_closure.load_manifest(missing)
        self.assertEqual(str(raised.exception), "cannot load manifest")

    def test_fd_faults_are_surface_errors(self):
        with mock.patch.object(surface_closure.os, "fstat", side_effect=OSError("boom")):
            with self.assertRaises(surface_closure.SurfaceError): surface_closure._fd_bytes(1, "file")
        with mock.patch.object(surface_closure.os, "read", side_effect=OSError("boom")):
            with mock.patch.object(surface_closure.os, "fstat", return_value=mock.Mock(st_mode=surface_closure.stat.S_IFREG)):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure._fd_bytes(1, "file")
        with mock.patch.object(surface_closure.os, "open", side_effect=OSError("boom")):
            with self.assertRaises(surface_closure.SurfaceError): surface_closure._open_relative(1, ("child",), "child")

    def test_graph_is_one_to_one_and_reachable(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        caps = manifest["capabilities"]
        self.assertEqual(len({c["name"] for c in caps}), len(caps))
        self.assertEqual(set(manifest["graph_accounting"]), set(surface_closure.EXPECTED_ACCOUNTING))
        self.assertEqual(manifest["graph_accounting"]["providers"], surface_closure.EXPECTED_ACCOUNTING["providers"])


class ClosureRequestCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.manifest = surface_closure.load_manifest(MANIFEST)

    def request(self, body=b'{"op_key":"x","payload":"y"}', target=b"/api/records/v1/main_ops"):
        return surface_closure.ClosureRequest(b"POST", target, ((b"Content-Type", b"application/json"),), body)

    def test_surrounding_json_whitespace_is_accepted(self):
        binding = surface_closure.bind_request(self.request(b' \t{"op_key":"x","payload":"y"}\n '), self.manifest)
        self.assertEqual(binding.operation_kind, "create_record")

    def test_trailing_non_whitespace_is_rejected(self):
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.bind_request(self.request(b'{"op_key":"x","payload":"y"}x'), self.manifest)


class SurfaceClosureTests(unittest.TestCase):
    def assert_semantic_mutation_rejected(self, mutate):
        with tempfile.TemporaryDirectory() as td:
            manifest, _, _ = synthetic_fixture(Path(td))
            mutate(manifest)
            with self.assertRaises(surface_closure.SurfaceError):
                surface_closure.validate_manifest(manifest)

    def test_manifest_is_pinned_and_complete(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        self.assertEqual(len(manifest["routes"]), 82)
        self.assertEqual(manifest["source"]["commit"], surface_closure.COMMIT)

    def test_complete_manifest_pin_rejects_security_metadata_changes(self):
        base = surface_closure.load_manifest(MANIFEST)
        mutations = [
            lambda m: m["source_files"][0].__setitem__("sha256", "0" * 64),
            lambda m: m["routes"][0]["source"].__setitem__("sha256", "0" * 64),
            lambda m: m["source"]["provenance"].__setitem__("sha256", "0" * 64),
            lambda m: m["source"].__setitem__("root", "other"),
            lambda m: m["source"]["provenance"].__setitem__("file", "other.json"),
            lambda m: m["routes"].__setitem__(0, {**m["routes"][0], "handler": "changed"}),
            lambda m: next(c for c in m["capabilities"] if c["edges"])["edges"].__setitem__(0, "route:GET /api/healthcheck"),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                candidate = copy.deepcopy(base); mutate(candidate)
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_manifest(candidate)

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
            with mock.patch.object(surface_closure, "PINNED_MANIFEST_SHA256", surface_closure._manifest_sha256(manifest)):
                surface_closure.verify_source(root, provenance, manifest)

    def test_route_handler_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["routes"][0].update(handler="changed_handler"))

    def test_route_section_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["routes"][0].update(section="auth"))

    def test_route_effects_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["routes"][0]["effects"].append("changed"))

    def test_route_secondary_effects_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["routes"][0]["secondary_effects"].append("changed"))

    def test_route_resolution_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["routes"][0].update(resolution="runtime_unknown"))

    def test_route_source_anchor_mutation_is_rejected(self):
        def mutate(m):
            route = m["routes"][0]
            entry = next(e for e in m["source_files"] if e["file"] == route["source"]["file"])
            anchor = {"line": route["source"]["line"] + 1, "contains": "changed route anchor"}
            entry["anchors"].append(anchor)
            route["source"].update(anchor)
            next(c for c in m["capabilities"] if c["name"] == f"route:{route['method']} {route['path']}")["source"].update(anchor)
        self.assert_semantic_mutation_rejected(mutate)

    def test_listener_anchor_mutation_is_rejected(self):
        def mutate(m):
            route = m["listener_route_instances"][0]
            anchor = next(a for e in m["source_files"] if e["file"] == route["source"]["file"] for a in e["anchors"] if a["line"] != route["source"]["line"])
            route["source"].update(anchor)
        self.assert_semantic_mutation_rejected(mutate)

    def test_capability_edge_mutation_preserving_reachability_is_rejected(self):
        def mutate(m):
            capability = next(c for c in m["capabilities"] if c["edges"])
            capability["edges"][0] = next(c["name"] for c in m["capabilities"] if c["name"] != capability["name"] and c["name"] not in capability["edges"])
        self.assert_semantic_mutation_rejected(mutate)

    def test_capability_source_anchor_mutation_is_rejected(self):
        def mutate(m):
            capability = next(c for c in m["capabilities"] if c["name"] == "route:GET /api/whoami")
            anchor = next(a for e in m["source_files"] if e["file"] == capability["source"]["file"] for a in e["anchors"] if a["line"] != capability["source"]["line"])
            capability["source"].update(anchor)
        self.assert_semantic_mutation_rejected(mutate)

    def test_debug_anchor_mutation_is_rejected(self):
        def mutate(m):
            route = m["debug_only_routes"][0]
            entry = next(e for e in m["source_files"] if e["file"] == route["source"]["file"])
            entry["anchors"].append({"line": 1, "contains": "/api/whoami"})
            route["source"].update(line=1, contains="/api/whoami")
        self.assert_semantic_mutation_rejected(mutate)

    def test_accounting_mutation_is_rejected(self):
        self.assert_semantic_mutation_rejected(lambda m: m["graph_accounting"]["routers"].reverse())

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
        def req(target, body=b'{"op_key":"x","payload":"y"}'):
            return surface_closure.ClosureRequest(b"POST", target, ((b"Content-Type", b"application/json"),), body)
        self.assertEqual(surface_closure.bind_request(req(b"/api/records/v1/main_ops"), manifest).database, "main")
        self.assertEqual(surface_closure.bind_request(req(b"/api/records/v1/aux_ops"), manifest).database, "aux")
        logout = b'{"refresh_token":"' + b"A" * 86 + b'"}'
        self.assertEqual(surface_closure.bind_request(req(b"/api/auth/v1/logout", logout), manifest).operation_kind, "logout_session")
        self.assertIsNone(surface_closure.bind_request(req(b"/api/records/v1/other"), manifest))

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
            with mock.patch.object(Path, "lstat", side_effect=OSError("boom")):
                with self.assertRaises(surface_closure.SurfaceError): surface_closure.verify_source(root, provenance, manifest)


class ArtifactReadLimitTests(unittest.TestCase):
    def test_descriptor_growth_stops_at_hard_limit(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "growing"
            path.write_bytes(b"x")
            fd = os.open(path, os.O_RDONLY)
            try:
                with mock.patch.object(surface_closure.os, "read", side_effect=(b"xxx", b"xxx", AssertionError("unbounded read"))) as read:
                    with self.assertRaises(surface_closure.SurfaceError):
                        surface_closure._fd_bytes(fd, "growing", max_bytes=4)
                self.assertEqual(read.call_count, 2)
            finally:
                os.close(fd)


class ClosureRequestTests(unittest.TestCase):
    MAIN_BODY = b'{"op_key":"native-main_ops","payload":"must-survive"}'
    AUX_BODY = b'{"op_key":"native-aux_ops","payload":"must-survive"}'
    LOGOUT_BODY = b'{"refresh_token":"' + b"A" * 86 + b'"}'
    HEADERS = ((b"content-type", b"application/json"),)

    @classmethod
    def setUpClass(cls):
        cls.manifest = surface_closure.load_manifest(MANIFEST)

    def request(self, *, method=b"POST", target=b"/api/records/v1/main_ops",
                headers=None, body=None):
        return surface_closure.ClosureRequest(
            method, target, self.HEADERS if headers is None else headers,
            self.MAIN_BODY if body is None else body)

    def assert_refused(self, request):
        try:
            binding = surface_closure.bind_request(request, self.manifest)
        except surface_closure.SurfaceError:
            return
        self.assertIsNone(binding)

    def test_exact_three_native_requests_bind(self):
        cases = (
            (self.request(), "create_record", "main"),
            (self.request(target=b"/api/records/v1/aux_ops", body=self.AUX_BODY), "create_record", "aux"),
            (self.request(target=b"/api/auth/v1/logout", body=self.LOGOUT_BODY), "logout_session", "session"),
        )
        for request, kind, database in cases:
            with self.subTest(target=request.target):
                binding = surface_closure.bind_request(request, self.manifest)
                self.assertEqual((binding.operation_kind, binding.database, binding.validated_request),
                                 (kind, database, request))

    def test_equivalent_json_and_header_name_case_bind(self):
        bodies = (
            b' { "payload" : "must-survive", "op_key" : "native-main_ops" } ',
            b'\n{"op_key":"n\\u0061tive-main_ops","payload":"must-survive"}\t',
        )
        for name in (b"content-type", b"Content-Type", b"CONTENT-TYPE"):
            for body in bodies:
                with self.subTest(name=name, body=body):
                    self.assertIsNotNone(surface_closure.bind_request(
                        self.request(headers=((name, b"application/json"),), body=body), self.manifest))

    def test_method_differentials_refuse(self):
        methods = (b"post", b"Post", b"GET", b"PUT", b"PATCH", b"DELETE", b"OPTIONS",
                   b"HEAD", b"POST ", b" POST", b"PO\x00ST", b"PO\nST", b"P\xffST", "POST", bytearray(b"POST"))
        for method in methods:
            with self.subTest(method=method):
                self.assert_refused(self.request(method=method))

    def test_target_differentials_refuse(self):
        targets = (b"/api/records/v1/main_ops?x=1", b"/api/records/v1/main_ops#x",
                   b"/api/records/v1/%6dain_ops", b"/api\\records/v1/main_ops",
                   b"/api/./records/v1/main_ops", b"/api/../records/v1/main_ops",
                   b"/api//records/v1/main_ops", b"/API/records/v1/main_ops",
                   b"/api/records/v1/Main_ops", b"/api/records/v1/main_ops/",
                   b"/api/records/v1/main_ops\x00", b"/api/records/v1/main_ops\n",
                   b"/api/records/v1/ma\xffin_ops", b"api/records/v1/main_ops",
                   b"/api/records/v1/other", "/api/records/v1/main_ops", bytearray(b"/api/records/v1/main_ops"))
        for target in targets:
            with self.subTest(target=target):
                self.assert_refused(self.request(target=target))

    def test_header_differentials_refuse(self):
        headers = (
            (), ((b"content-type", b"application/json"), (b"content-type", b"application/json")),
            ((b" content-type", b"application/json"),), ((b"content-type ", b"application/json"),),
            ((b"\tcontent-type", b"application/json"),), ((b"content-type", b" application/json"),),
            ((b"content-type", b"application/json "),), ((b"content-type", b"Application/Json"),),
            ((b"content-type", b"application/json; charset=utf-8"),),
            ((b"content-type", b"multipart/form-data"),), ((b"content-type", b"application/x-www-form-urlencoded"),),
            ((b"content-type", b"application/json\n"),), ((b"cont\x00ent-type", b"application/json"),),
            ((b"cont\xffent-type", b"application/json"),), ((b"authorization", b"x"),),
            ((b"content-type", b"application/json"), (b"host", b"localhost")),
            ([b"content-type", b"application/json"],), (("content-type", b"application/json"),),
            ((b"content-type", "application/json"),), [(b"content-type", b"application/json")],
        )
        for value in headers:
            with self.subTest(headers=value):
                self.assert_refused(self.request(headers=value))

    def test_record_body_differentials_refuse(self):
        bodies = (
            b"", b"{}", b"[]", b"null", b"true", b"1", b'"x"', b"{", b"\xff",
            b'{"op_key":"a","op_key":"b","payload":"x"}',
            b'{"op_key":"a","payload":NaN}', b'{"op_key":"a","payload":Infinity}',
            b'{"op_key":"a","payload":"x"}garbage',
            b'{"op_key":"a"}', b'{"payload":"x"}', b'{"op_key":"a","payload":"x","extra":1}',
            b'{"op_key":1,"payload":"x"}', b'{"op_key":"a","payload":1}',
            b'{"op_key":"","payload":"x"}', b'{"op_key":"a","payload":""}',
            json.dumps({"op_key": "a" * 1025, "payload": "x"}).encode(),
            json.dumps({"op_key": "a", "payload": "x" * 1025}).encode(),
            b"x=" + self.MAIN_BODY, b"--boundary\r\n" + self.MAIN_BODY,
            bytearray(self.MAIN_BODY), b"x" * (surface_closure.MAX_ARTIFACT_BYTES + 1),
        )
        for body in bodies:
            with self.subTest(body=repr(body)[:80]):
                self.assert_refused(self.request(body=body))

    def test_logout_body_differentials_refuse(self):
        invalid = (b"{}", b"[]", b'{"refresh_token":1}', b'{"refresh_token":"A"}',
                   b'{"refresh_token":"' + b"A" * 85 + b'"}',
                   b'{"refresh_token":"' + b"A" * 87 + b'"}',
                   b'{"refresh_token":"' + b"!" * 86 + b'"}',
                   b'{"refresh_token":"' + b"A" * 86 + b'","extra":1}',
                   b'{"refresh_token":"' + b"A" * 86 + b'","refresh_token":"' + b"A" * 86 + b'"}')
        for body in invalid:
            with self.subTest(body=repr(body)[:80]):
                self.assert_refused(self.request(target=b"/api/auth/v1/logout", body=body))

    def test_binding_and_nested_request_are_immutable(self):
        request = self.request()
        binding = surface_closure.bind_request(request, self.manifest)
        for obj, field, value in ((request, "body", b"changed"), (binding, "database", "aux"),
                                  (binding.validated_request, "headers", ())):
            with self.subTest(field=field):
                with self.assertRaises(FrozenInstanceError):
                    setattr(obj, field, value)
        with self.assertRaises(TypeError):
            binding.validated_request.headers[0][0] = b"changed"
        self.assertEqual(set(binding.__dataclass_fields__), {"operation_kind", "database", "validated_request"})

    def test_raw_byte_differentials_refuse_before_callback(self):
        calls = 0
        def attempt(request):
            nonlocal calls
            try:
                binding = surface_closure.bind_request(request, self.manifest)
            except surface_closure.SurfaceError:
                return
            if binding is not None:
                calls += 1
        for route in self.manifest["routes"]:
            with self.subTest(route=(route["method"], route["path"])):
                attempt(self.request(method=route["method"].encode("ascii"),
                                     target=route["path"].encode("ascii"), body=b"{}"))
                self.assertEqual(calls, 0)
        near_misses = (
            self.request(target=b"/api/records/v1/main_ops/1"),
            self.request(target=b"/api/records/v1/main_op"),
            self.request(target=b"/api/records/v1/aux_ops/1", body=self.AUX_BODY),
            self.request(target=b"/api/auth/v1/logout/", body=self.LOGOUT_BODY),
            self.request(target=b"/api/auth/v1/logout", body=b"{}"),
        )
        for request in near_misses:
            attempt(request)
            self.assertEqual(calls, 0)


def valid_attestation_fixture():
    manifest = surface_closure.load_manifest(MANIFEST)
    h = "a" * 64
    conditions = {
        "config:anonymous_enabled": "disabled", "config:otp_enabled": "disabled",
        "config:sqlite": "enabled", "config:transactions_enabled": "disabled",
        "conditional:transactions-enabled": "disabled",
        "conditional:records-subscribe-sqlite": "enabled",
        "conditional:auth-anonymous-signin": "disabled",
        "conditional:auth-otp-signin": "disabled",
        "conditional:wasm-feature": "absent",
        "conditional:independent-admin-listener": "enabled",
        "conditional:public-dir": "absent", "conditional:public-dir-spa": "absent",
        "conditional:auth-rate-limit": "disabled",
    }
    request_hashes = (("create_main", "a" * 64), ("create_aux", "b" * 64), ("logout_session", "c" * 64))
    trust = surface_closure.AttestationTrust(
        h, "b" * 64, 10, 30, 10, "c" * 64, 20, 90, 501, (20,),
        surface_closure._manifest_sha256(manifest), "d" * 64, "e" * 64,
        "f" * 64, "1" * 64, "trailbase-build", "2" * 64, 7, "3" * 64,
        "4" * 64, "5" * 64, 9, "6" * 64, 100, 110, 200,
        ("trail", "serve"), (("PATH", "/usr/bin"),), request_hashes, tuple(conditions.items()),
        ("/private/q/main.db", "/private/q/session.db", "/private/q/config"),
        "/private/q/logs.db", "manager-nonce", "0" * 64)
    evidence = []
    sequence = 0
    def ev(kind):
        nonlocal sequence
        sequence += 1
        ident = f"e{sequence}"
        evidence.append({"id": ident, "path": f"{ident}.json", "sha256": f"{sequence % 16:x}" * 64,
                         "size": 1, "kind": kind, "collector_source_sha256": trust.collector_source_sha256,
                         "created_mono_ns": 150})
        return ident
    ancestry = [{"path": "/private", "uid": 501, "mode": 0o700, "symlink": False},
                {"path": "/private/q", "uid": 501, "mode": 0o700, "symlink": False}]
    listeners = [
        {"id": "main", "pid": 20, "role": "main", "protocol": "AF_UNIX", "sock_type": "SOCK_STREAM",
         "path": "/private/q/main.sock", "parent_ancestry": copy.deepcopy(ancestry), "uid": 501,
         "mode": 0o600, "device": 1, "inode": 101, "nlink": 1, "source": "observed"},
        {"id": "admin", "pid": 20, "role": "admin", "protocol": "AF_UNIX", "sock_type": "SOCK_STREAM",
         "path": "/private/q/admin.sock", "parent_ancestry": copy.deepcopy(ancestry), "uid": 501,
         "mode": 0o600, "device": 1, "inode": 102, "nlink": 1, "source": "observed"},
    ]
    tree = [
        {"pid": 10, "parent_pid": 0, "start_mono_ns": 1, "uid": 501, "gids": [20],
         "exe_sha256": "7" * 64, "argv": ["manager"], "role": "manager"},
        {"pid": 20, "parent_pid": 10, "start_mono_ns": 90, "uid": 501, "gids": [20],
         "exe_sha256": trust.binary_sha256, "argv": list(trust.expected_argv), "role": "trailbase"},
        {"pid": 30, "parent_pid": 10, "start_mono_ns": 110, "uid": 501, "gids": [20],
         "exe_sha256": trust.collector_source_sha256, "argv": ["collector"], "role": "collector"},
    ]
    descriptors = []
    for proc in tree:
        for fd, kind in enumerate(("stdin", "stdout", "stderr")):
            descriptors.append({"pid": proc["pid"], "fd": fd, "cloexec": False, "owner_uid": proc["uid"],
                                "process_role": proc["role"], "type": kind, "path": None,
                                "inode": 0, "device": 0, "mode": 0, "nlink": 1, "source": "observed"})
    for fd, listener in enumerate(listeners, 3):
        descriptors.append({"pid": 20, "fd": fd, "cloexec": True, "owner_uid": 501,
                            "process_role": "trailbase", "type": "uds", "path": listener["path"],
                            "inode": listener["inode"], "device": listener["device"], "mode": 0o600,
                            "nlink": 1, "source": "observed"})
    for index in range(3):
        descriptors.append({"pid": 10, "fd": index + 3, "cloexec": True, "owner_uid": 501,
                            "process_role": "manager", "type": "uds", "path": listeners[0]["path"],
                            "inode": 200 + index, "device": 1, "mode": 0o600, "nlink": 1,
                            "source": "observed"})
    bindings = [{"listener_id": x["id"], "inode": x["inode"], "device": x["device"], "pid": 20,
                 "exe_sha256": trust.binary_sha256, "argv": list(trust.expected_argv),
                 "observed_mono_ns": 140, "source": "observed", "evidence_id": ev("socket")}
                for x in listeners]
    connections = []
    for index, listener in enumerate((listeners[0], listeners[0], listeners[0])):
        connections.append({"id": f"conn{index}", "listener_id": listener["id"], "client_pid": 10,
            "server_pid": 20, "client_uid": 501, "client_gids": [20], "server_uid": 501,
            "server_gids": [20], "client_device": 1, "client_inode": 200 + index, "server_device": listener["device"], "server_inode": listener["inode"],
            "accepted_mono_ns": 130 + index, "peer_source": "LOCAL_PEERCRED",
            "bytes_before_validation": 0, "evidence_id": ev("socket")})
    route_regs = []
    for route in manifest["routes"]:
        condition = route["condition"]
        route_regs.append({"method": route["method"], "path": route["path"], "handler": route["handler"],
            "enabled": condition == "always" or conditions[condition] == "enabled",
            "source_sha256": route["source"]["sha256"], "condition_id": condition,
            "evidence_id": ev("registration")})
    caps = {x["name"]: x for x in manifest["capabilities"]}
    jobs = [{"id": "job:" + name, "enabled": False, "mutates": True,
             "source_sha256": caps["job:" + name]["source"]["sha256"], "condition_id": "always",
             "evidence_id": ev("registration")} for name in surface_closure.REQUIRED_JOBS]
    condition_regs = [{"id": key, "expression": key, "resolution": value, "observed_by": "collector",
                       "evidence_id": ev("registration")} for key, value in conditions.items()]
    dynamic = [{"point_id": cap["name"], "kind": "dynamic_router",
                "source_sha256": cap["source"]["sha256"], "query": "content-addressed absence",
                "expected_absent": True, "observed_absent": True, "evidence_id": ev("absence")}
               for cap in manifest["capabilities"] if cap["class"] == "dynamic_router"]
    probes = [{"path": path, "uid": 501, "operation": "create", "result": "denied", "errno": 13,
               "evidence_id": ev("probe")} for path in trust.protected_paths]
    telemetry = {"logs_only": True,
        "readers": [{"pid": 20, "operation": "read", "path": trust.logs_path, "evidence_id": ev("descriptor")}],
        "writers": [{"pid": 20, "operation": "write", "path": trust.logs_path, "evidence_id": ev("descriptor")}]}
    evidence.append({"id": "receipt", "path": "receipt.json", "sha256": "9" * 64, "size": 1,
                     "kind": "receipt", "collector_source_sha256": trust.collector_source_sha256,
                     "created_mono_ns": 150})
    attestation = {
        "schema": surface_closure.ATTESTATION_SCHEMA,
        "collector": {"id": "collector", "source_sha256": trust.collector_source_sha256,
            "pid": 30, "parent_pid": 10, "started_wall": "2026-09-09T00:00:00Z", "started_mono_ns": 111,
            "finished_wall": "2026-09-09T00:00:01Z", "finished_mono_ns": 190},
        "manager_receipt": {"path_sha256": trust.manager_receipt_path_sha256,
            "receipt_sha256": trust.manager_receipt_sha256, "nonce": trust.manager_receipt_nonce,
            "manager_pid": 10, "collector_pid": 30, "collector_parent_pid": 10,
            "launched_mono_ns": 110, "exited_mono_ns": 195},
        "source": {"repo": "trailbaseio/trailbase", "tag": "v0.33.11", "commit": surface_closure.COMMIT,
            "sha256": trust.source_sha256, "root_sha256": trust.source_root_sha256},
        "binary": {"path_sha256": trust.binary_path_sha256, "sha256": trust.binary_sha256,
                   "build_id": trust.build_id},
        "config": {"sha256": trust.config_sha256, "generation": 7, "files": []},
        "migration": {"sha256": trust.migration_sha256, "files": []},
        "plugin": {"sha256": trust.plugin_sha256, "files": [], "registrations": []},
        "sandbox": {"profile_sha256": trust.sandbox_profile_sha256, "profile_generation": 9,
                    "identity_uid": 501, "identity_groups": [20], "root_sha256": trust.sandbox_root_sha256},
        "launch": {"argv": list(trust.expected_argv), "env": [{"name": "PATH", "value": "/usr/bin"}],
                   "process_tree": tree, "env_i": True},
        "window": {"ready_mono_ns": 100, "start_mono_ns": 120, "end_mono_ns": 180,
            "positive_controls": [{"kind": kind, "request_sha256": digest,
                "connection_id": f"conn{index}", "start_mono_ns": 140 + index * 5,
                "end_mono_ns": 141 + index * 5, "evidence_id": connections[index]["evidence_id"]}
                for index, (kind, digest) in enumerate(request_hashes)]},
        "descriptors": descriptors, "listeners": listeners, "connections": connections,
        "listener_bindings": bindings,
        "registrations": {"jobs": jobs, "plugins": [], "routes": route_regs,
                          "conditions": condition_regs, "dynamic_absence": dynamic},
        "writable_probes": probes, "evidence": evidence,
        "uncertainty": {"unknown": [], "missing": [], "extra": [], "stale": [], "self_reported_only": []},
        "telemetry": telemetry, "attestation_sha256": "0" * 64,
    }
    attestation["attestation_sha256"] = surface_closure._canonical_digest(attestation, "attestation_sha256")
    trust = replace(trust, attestation_sha256=attestation["attestation_sha256"])
    return manifest, trust, attestation


def resigned(attestation, trust):
    attestation["attestation_sha256"] = surface_closure._canonical_digest(attestation, "attestation_sha256")
    return replace(trust, attestation_sha256=attestation["attestation_sha256"])


class AttestationTests(unittest.TestCase):
    def test_valid_independent_attestation_is_immutable(self):
        manifest, trust, attestation = valid_attestation_fixture()
        result = surface_closure.validate_attestation(attestation, manifest, trust)
        self.assertEqual(result["status"], "feasible")
        with self.assertRaises(TypeError): result["status"] = "changed"

    def test_missing_extra_stale_or_self_reported_facts_are_infeasible(self):
        manifest, trust, base = valid_attestation_fixture()
        for key in base["uncertainty"]:
            with self.subTest(key=key):
                value = copy.deepcopy(base); value["uncertainty"][key] = ["x"]
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, resigned(value, trust))
        mutations = [
            lambda x: x["collector"].__setitem__("extra", True),
            lambda x: x["manager_receipt"].__setitem__("nonce", "fixture-copy"),
            lambda x: x["listeners"][0].__setitem__("source", "declared"),
            lambda x: x["registrations"]["conditions"][0].__setitem__("observed_by", "declaration"),
            lambda x: x["evidence"][0].__setitem__("created_mono_ns", 201),
        ]
        for mutate in mutations:
            value = copy.deepcopy(base); mutate(value)
            with self.assertRaises(surface_closure.SurfaceError):
                surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_trust_and_timing_are_cross_bound(self):
        manifest, trust, value = valid_attestation_fixture()
        changes = {"manager_pid": 11, "fixture_pid": 21, "service_uid": 502,
                   "build_id": "other", "collection_deadline_mono_ns": 179,
                   "manager_receipt_nonce": "other", "attestation_sha256": "f" * 64}
        for field, changed in changes.items():
            with self.subTest(field=field):
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, replace(trust, **{field: changed}))
        for path in (("collector","finished_mono_ns",201), ("manager_receipt","exited_mono_ns",109),
                     ("window","end_mono_ns",201)):
            changed = copy.deepcopy(value); changed[path[0]][path[1]] = path[2]
            with self.assertRaises(surface_closure.SurfaceError):
                surface_closure.validate_attestation(changed, manifest, resigned(changed, trust))

    def test_process_descriptor_listener_and_connection_mismatches_refuse(self):
        manifest, trust, base = valid_attestation_fixture()
        mutations = [
            lambda x: x["launch"]["process_tree"][1].__setitem__("pid", 99),
            lambda x: x["launch"]["process_tree"][2].__setitem__("parent_pid", 20),
            lambda x: x["launch"]["process_tree"][0].__setitem__("parent_pid", 30),
            lambda x: x["descriptors"][0].__setitem__("source", "declared"),
            lambda x: x["descriptors"][0].__setitem__("mode", -1),
            lambda x: x["descriptors"][0].__setitem__("nlink", -1),
            lambda x: x["descriptors"][0].__setitem__("inode", 10 ** 100),
            lambda x: x["descriptors"].append({**x["descriptors"][0], "fd": 9, "cloexec": False}),
            lambda x: x["descriptors"].append({**next(d for d in x["descriptors"] if d["pid"] == 10 and d["fd"] == 3), "fd": 99, "path": "/arbitrary.sock", "inode": 999}),
            lambda x: x["listeners"][0].__setitem__("protocol", "AF_INET"),
            lambda x: x["listeners"][0].__setitem__("inode", 999),
            lambda x: x["listeners"][0]["parent_ancestry"][0].__setitem__("symlink", True),
            lambda x: x["listener_bindings"][0].__setitem__("inode", 999),
            lambda x: x["connections"][0].__setitem__("server_uid", 999),
            lambda x: x["connections"][0].__setitem__("client_inode", -1),
            lambda x: x["connections"][0].__setitem__("client_inode", 999),
            lambda x: x["connections"][0].__setitem__("bytes_before_validation", 1),
            lambda x: x["connections"][0].__setitem__("peer_source", "declared"),
            lambda x: (x["connections"][0].update(client_pid=20, client_uid=501, client_gids=[20], client_device=1, client_inode=101),),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(base); mutate(value)
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_connection_cardinality_rejects_uncontrolled_manager_socket(self):
        manifest, trust, base = valid_attestation_fixture()
        value = copy.deepcopy(base)
        extra = copy.deepcopy(value["connections"][0])
        extra.update(id="conn3", client_inode=203, evidence_id="extra-socket")
        value["connections"].append(extra)
        value["descriptors"].append({**next(d for d in value["descriptors"] if d["pid"] == 10 and d["fd"] == 3), "fd": 6, "inode": 203})
        value["evidence"].append({**next(e for e in value["evidence"] if e["id"] == "e1"), "id": "extra-socket", "path": "extra-socket.json"})
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_connection_server_device_must_match_listener(self):
        manifest, trust, base = valid_attestation_fixture()
        value = copy.deepcopy(base)
        value["connections"][0]["server_device"] = 2
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_registration_evidence_probe_and_telemetry_mismatches_refuse(self):
        manifest, trust, base = valid_attestation_fixture()
        mutations = [
            lambda x: x["registrations"]["jobs"][0].__setitem__("enabled", True),
            lambda x: x["registrations"]["jobs"].pop(),
            lambda x: x["registrations"]["plugins"].append({}),
            lambda x: x["registrations"]["routes"][0].__setitem__("handler", "other"),
            lambda x: x["registrations"]["routes"].pop(),
            lambda x: x["registrations"]["conditions"][0].__setitem__("resolution", "runtime_unknown"),
            lambda x: x["registrations"]["dynamic_absence"].pop(),
            lambda x: x["registrations"]["dynamic_absence"][0].__setitem__("observed_absent", False),
            lambda x: x["evidence"][0].__setitem__("collector_source_sha256", "f" * 64),
            lambda x: x["evidence"][0].__setitem__("size", -1),
            lambda x: x["evidence"].append(copy.deepcopy(x["evidence"][0])),
            lambda x: x["evidence"][1].__setitem__("path", x["evidence"][0]["path"]),
            lambda x: x["evidence"].pop(0),
            lambda x: x["writable_probes"][0].__setitem__("result", "allowed"),
            lambda x: x["writable_probes"][0].__setitem__("path", "/outside"),
            lambda x: x["telemetry"]["writers"][0].__setitem__("path", "/private/q/main.db"),
            lambda x: x["telemetry"].__setitem__("logs_only", False),
            lambda x: (x["connections"][0].update(listener_id="admin", server_inode=102),
                       next(d for d in x["descriptors"] if d["pid"] == 10 and d["inode"] == 200).update(path="/private/q/admin.sock")),
            lambda x: [control.__setitem__("connection_id", "conn0") for control in x["window"]["positive_controls"]],
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(base); mutate(value)
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_every_attestation_object_has_exact_schema(self):
        manifest, trust, base = valid_attestation_fixture()
        for key in tuple(base):
            with self.subTest(top_missing=key):
                value = copy.deepcopy(base); value.pop(key)
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, trust)
        value = copy.deepcopy(base); value["extra"] = True
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(value, manifest, resigned(value, trust))
        nested = ("collector","manager_receipt","source","binary","config","migration","plugin",
                  "sandbox","launch","window","uncertainty","telemetry","registrations")
        for name in nested:
            first = next(iter(base[name]))
            for action in ("missing", "extra"):
                with self.subTest(object=name, action=action):
                    value = copy.deepcopy(base)
                    if action == "missing": value[name].pop(first)
                    else: value[name]["extra"] = True
                    with self.assertRaises(surface_closure.SurfaceError):
                        surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_malformed_nested_types_are_surface_errors(self):
        manifest, trust, base = valid_attestation_fixture()
        mutations = [
            lambda x: x.__setitem__("collector", []),
            lambda x: x["collector"].__setitem__("pid", True),
            lambda x: x["launch"].__setitem__("argv", "trail"),
            lambda x: x["launch"]["process_tree"].__setitem__(0, {}),
            lambda x: x.__setitem__("descriptors", {}),
            lambda x: x["descriptors"].__setitem__(0, []),
            lambda x: x["listeners"].__setitem__(0, {}),
            lambda x: x["connections"].__setitem__(0, {}),
            lambda x: x["listener_bindings"].__setitem__(0, {}),
            lambda x: x["registrations"].__setitem__("routes", {}),
            lambda x: x["writable_probes"].__setitem__(0, {}),
            lambda x: x["evidence"].__setitem__(0, {}),
            lambda x: x["telemetry"].__setitem__("readers", {}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = copy.deepcopy(base); mutate(value)
                with self.assertRaises(surface_closure.SurfaceError):
                    surface_closure.validate_attestation(value, manifest, resigned(value, trust))

    def test_external_digest_and_positive_request_hashes_are_mandatory(self):
        manifest, trust, base = valid_attestation_fixture()
        value = copy.deepcopy(base); value["collector"]["id"] = "rewritten"
        value["attestation_sha256"] = surface_closure._canonical_digest(value, "attestation_sha256")
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(value, manifest, trust)
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(base, manifest, replace(trust, attestation_sha256=""))
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_attestation(base, manifest, replace(trust, positive_request_sha256=(("create_main", "a" * 64),)))

    def test_failures_never_reach_positive_callback(self):
        manifest, trust, base = valid_attestation_fixture()
        calls = 0
        def attempt(value, expected):
            nonlocal calls
            try: surface_closure.validate_attestation(value, manifest, expected)
            except surface_closure.SurfaceError: return
            calls += 1
        failures = []
        for key in base["uncertainty"]:
            value = copy.deepcopy(base); value["uncertainty"][key] = ["x"]
            failures.append((value, resigned(value, trust)))
        value = copy.deepcopy(base); value["writable_probes"][0]["result"] = "allowed"
        failures.append((value, resigned(value, trust)))
        for value, expected in failures: attempt(value, expected)
        self.assertEqual(calls, 0)

if __name__ == "__main__":
    unittest.main()

class QuarantineTests(unittest.TestCase):
    def test_only_canonical_private_manifested_roots_pass(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "q"
            root.mkdir(mode=0o700)
            payload = b"safe"
            (root / "payload").write_bytes(payload)
            (root / "payload").chmod(0o600)
            (root / "access.log").write_bytes(b"")
            (root / "access.log").chmod(0o600)
            uid = os.getuid()
            m = {"schema":"d4-quarantine-1", "root":str(root.resolve()), "owner_uid":uid,
                 "disposition":"pending", "files":[{"path":"payload","sha256":hashlib.sha256(payload).hexdigest(),"size":4,"mode":0o600,"nlink":1,"kind":"regular"}],
                 "file_count":1,"byte_total":4,"hash_algorithm":"sha256","manifest_sha256":"","access_log":str((root/"access.log").resolve())}
            m["manifest_sha256"] = surface_closure._canonical_digest(m, "manifest_sha256")
            (root / "manifest.json").write_text(json.dumps(m, sort_keys=True, separators=(",", ":")))
            result = surface_closure.validate_quarantine(root, m)
            self.assertTrue(result["feasible"])
            with self.assertRaises(TypeError): result["feasible"] = False

    def test_quarantine_rejects_tamper_and_links(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "q"; root.mkdir(mode=0o700)
            (root / "access.log").write_bytes(b""); (root / "access.log").chmod(0o600)
            data = b"x"; (root / "payload").write_bytes(data); (root / "payload").chmod(0o600)
            m = {"schema":"d4-quarantine-1", "root":str(root.resolve()), "owner_uid":os.getuid(), "disposition":"pending", "files":[{"path":"payload","sha256":hashlib.sha256(data).hexdigest(),"size":1,"mode":384,"nlink":1,"kind":"regular"}], "file_count":1,"byte_total":1,"hash_algorithm":"sha256","manifest_sha256":"","access_log":str((root/"access.log").resolve())}
            m["manifest_sha256"] = surface_closure._canonical_digest(m, "manifest_sha256")
            (root / "manifest.json").write_text(json.dumps(m, sort_keys=True, separators=(",", ":")))
            (root / "payload").write_bytes(b"tampered")
            with self.assertRaises(surface_closure.SurfaceError): surface_closure.validate_quarantine(root, m)
