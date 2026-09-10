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
            token = f"synthetic inventory {index} {anchor_index}"
            lines[anchor["line"] - 1] += f" {token}"
            anchor["contains"] = token
        data = ("\n".join(lines) + "\n").encode("utf-8")
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
    for route_index, route in enumerate(manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]):
        source = route["source"]
        token = f"synthetic route {route_index}"
        path = root / source["file"]
        data = path.read_text().splitlines()
        data[source["line"] - 1] += f" {token}"
        path.write_text("\n".join(data) + "\n")
        source["contains"] = token
    for entry in manifest["source_files"]:
        digest = hashlib.sha256((root / entry["file"]).read_bytes()).hexdigest()
        entry["sha256"] = digest
        for route in manifest["routes"] + manifest["debug_only_routes"] + manifest["listener_route_instances"]:
            if route["source"]["file"] == entry["file"]:
                route["source"]["sha256"] = digest
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
        self.assertEqual(set(manifest["graph_accounting"]["routes"]), {f"route:{r['method']} {r['path']}" for r in manifest["routes"]})


class SurfaceClosureTests(unittest.TestCase):
    def test_manifest_is_pinned_and_complete(self):
        manifest = surface_closure.load_manifest(MANIFEST)
        self.assertEqual(len(manifest["routes"]), 82)
        self.assertEqual(manifest["source"]["commit"], surface_closure.COMMIT)


if __name__ == "__main__":
    unittest.main()
