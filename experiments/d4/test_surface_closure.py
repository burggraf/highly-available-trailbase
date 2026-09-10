import copy
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

            def checked_fd_bytes(fd, name, identity=None):
                if name != "provenance": self.assertEqual(rs_opens, expected_count)
                return real_fd_bytes(fd, name, identity)

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

            def checked_fd_bytes(fd, name, identity=None):
                if name != "provenance":
                    self.assertEqual(len(identities), expected_count)
                    self.assertEqual(identity, identities[fd])
                return real_fd_bytes(fd, name, identity)

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

if __name__ == "__main__":
    unittest.main()
