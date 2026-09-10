import json
from pathlib import Path
import tempfile
import unittest

import surface_closure


class SurfaceClosureTests(unittest.TestCase):
    def test_manifest_is_pinned_and_complete(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        self.assertEqual(len(manifest["routes"]), 82)
        self.assertEqual(manifest["source"]["commit"], "f24291b894bb6c6696608e5f4c2f68666fe97686")
        route_keys = {(r["method"], r["path"]) for r in manifest["routes"]}
        self.assertIn(("DELETE", "/api/auth/v1/delete"), route_keys)
        self.assertEqual({(r["method"], r["path"]) for r in manifest["routes"] if r["classification"] == "allow"}, set(surface_closure.ALLOWED))
        self.assertTrue({"router", "conditional", "job", "dynamic_router", "listener", "direct_writer", "provider", "telemetry"} <= {c["class"] for c in manifest["capabilities"]})

    def test_tampered_source_is_rejected(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        source = manifest["routes"][0]["source"]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / source["file"]).parent.mkdir(parents=True)
            (root / source["file"]).write_text("tampered\n")
            with self.assertRaises(surface_closure.SurfaceError):
                surface_closure.verify_source(root, root / "manifest.json", manifest)

    def test_wrong_allowlist_is_rejected(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["routes"][0]["classification"] = "allow"
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_manifest(manifest)

    def test_missing_delete_and_duplicate_pair_are_rejected(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["routes"] = [r for r in manifest["routes"] if r["path"] != "/api/auth/v1/delete"]
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_manifest(manifest)
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["routes"][1]["method"] = manifest["routes"][0]["method"]
        manifest["routes"][1]["path"] = manifest["routes"][0]["path"]
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_manifest(manifest)

    def test_runtime_unknown_and_unresolved_graph_are_rejected(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["unresolved_source_graph"] = ["generated router"]
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_manifest(manifest)
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["routes"][0]["classification"] = "runtime_unknown"
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.validate_eligibility_input(manifest)

    def test_bad_anchor_and_provenance_are_rejected(self):
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["routes"][0]["source"]["line"] = 1
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.verify_source(Path("/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/trailbase"), Path("/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/manifest.json"), manifest)
        manifest = surface_closure.load_manifest(Path(__file__).with_name("surface_manifest.json"))
        manifest["source"]["provenance"]["sha256"] = "0" * 64
        with self.assertRaises(surface_closure.SurfaceError):
            surface_closure.verify_source(Path("/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/trailbase"), Path("/var/folders/d0/z9jph2ld4v9gw45bwg0f1j900000gn/T/hat-ack-contract-sources-p2anepgt/manifest.json"), manifest)


if __name__ == "__main__":
    unittest.main()
