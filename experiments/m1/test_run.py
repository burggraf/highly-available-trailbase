import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from run import (Node, RunContext, append_evidence, load_inventory,
                 new_run_context, require_private_file, ssh, validate_inventory,
                 redact)


def inventory():
    return {"nodes": [
        {"name": "a", "ssh": "root@a.example", "instance_id": 1,
         "provider_label": "a", "address": "a.example", "host_key": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"name": "b", "ssh": "root@b.example", "instance_id": 2,
         "provider_label": "b", "address": "b.example", "host_key": "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"},
        {"name": "c", "ssh": "root@c.example", "instance_id": 3,
         "provider_label": "c", "address": "c.example", "host_key": "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"},
    ]}


class InventoryTests(unittest.TestCase):
    def test_validates_and_returns_nodes(self):
        self.assertEqual(len(validate_inventory(inventory())), 3)

    def test_rejects_unknown_keys_and_duplicates(self):
        value = inventory(); value["extra"] = 1
        with self.assertRaises(ValueError): validate_inventory(value)
        value = inventory(); value["nodes"][1]["instance_id"] = 1
        with self.assertRaises(ValueError): validate_inventory(value)

    def test_rejects_non_root_and_too_few(self):
        value = inventory(); value["nodes"][0]["ssh"] = "hat@a.example"
        with self.assertRaises(ValueError): validate_inventory(value)
        with self.assertRaises(ValueError): validate_inventory({"nodes": []})

    def test_private_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secret"; p.write_text("x"); p.chmod(0o600)
            self.assertIsNone(require_private_file(p))
            p.chmod(0o644)
            with self.assertRaises(ValueError): require_private_file(p)

class TransportTests(unittest.TestCase):
    def test_remote_arguments_are_shell_quoted(self):
        node = Node("a", "root@a", 1, "a", "a", "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        with mock.patch("run.subprocess.run") as call, mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/known_hosts")):
            ssh(node, ["printf", "hello; rm -rf /"])
        self.assertEqual(call.call_args.args[0][-1], "printf 'hello; rm -rf /'")

class ContextTests(unittest.TestCase):
    def test_new_context_is_fresh_private(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = new_run_context(Path(d), repository=Path(d) / "repo")
            self.assertEqual(stat.S_IMODE(ctx.local_root.stat().st_mode), 0o700)
            self.assertTrue(ctx.remote_root.startswith("/var/lib/hat-qualification/"))

class EvidenceTests(unittest.TestCase):
    def test_redacts_sensitive_values_and_fsyncs_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "evidence.jsonl"
            append_evidence(p, {"password": "secret", "nested": {"token": "x"}})
            data = p.read_text()
            self.assertNotIn("secret", data); self.assertNotIn('"x"', data)
            self.assertEqual(json.loads(data)["password"], "[REDACTED]")

if __name__ == "__main__": unittest.main()
