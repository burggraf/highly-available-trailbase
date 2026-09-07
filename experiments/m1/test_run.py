import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from run import (
    Node, RunContext, _FINGERPRINT, _require_facts, _known_host_fingerprint,
    append_evidence, build_pinned_known_hosts, ensure_remote_root, init_remote,
    load_inventory, load_linode_env, new_run_context, require_private_file,
    redact, scp_to, ssh, validate_inventory, _absolute_no_symlinks, main,
)

FP = "SHA256:" + "A" * 43

def inventory(names=("a", "b", "c")):
    return {"nodes": [
        {"name": n, "ssh": f"root@{n}.example", "instance_id": i,
         "provider_label": n, "address": f"{n}.example", "host_key": "SHA256:" + chr(64 + i) * 43, "hostname": f"{n}.example"}
        for i, n in enumerate(names, 1)
    ]}

def node(name="a"):
    return Node(name, f"root@{name}", 1, name, name, FP, name)

def facts(host="a"):
    return {"hostname": host, "release": "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
            "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
            "memory": "MemTotal:       1048576 kB\n", "cpu": "2",
            "disk": "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1 1 1 10% /\n",
            "time_sync": "NTPSynchronized=yes\n", "outbound_tls": "HAT_M1_TLS_OK\n"}

class InventoryTests(unittest.TestCase):
    def test_validates_and_returns_nodes(self):
        self.assertEqual(len(validate_inventory(inventory(("fm1", "fm2", "fm3")))), 3)

    def test_inventory_requires_exact_fm_node_set(self):
        for names in (("a", "b", "c"), ("fm1", "fm2", "other"), ("fm1", "fm2", "fm2")):
            with self.assertRaises(ValueError): validate_inventory(inventory(names))

    def test_rejects_unknown_keys_and_duplicates(self):
        value = inventory(); value["extra"] = 1
        with self.assertRaises(ValueError): validate_inventory(value)
        value = inventory(); value["nodes"][1]["instance_id"] = 1
        with self.assertRaises(ValueError): validate_inventory(value)

    def test_hostname_duplicates_are_not_identity_duplicates(self):
        value = inventory(("fm1", "fm2", "fm3"))
        value["nodes"][1]["hostname"] = value["nodes"][0]["hostname"] = "localhost"
        self.assertEqual(len(validate_inventory(value)), 3)

    def test_rejects_duplicate_address_label_and_fingerprint(self):
        for field in ("address", "provider_label", "host_key", "name"):
            value = inventory(); value["nodes"][1][field] = value["nodes"][0][field]
            with self.assertRaises(ValueError): validate_inventory(value)

    def test_rejects_non_root_and_wrong_target(self):
        value = inventory(); value["nodes"][0]["ssh"] = "hat@a.example"
        with self.assertRaises(ValueError): validate_inventory(value)
        value = inventory(); value["nodes"][0]["ssh"] = "root@other.example"
        with self.assertRaises(ValueError): validate_inventory(value)

    def test_rejects_malformed_endpoint_names(self):
        for field in ("address", "hostname"):
            for value in (".bad", "bad.", "bad..name", "bad_name", "-bad", "bad-"):
                value_data = inventory()
                value_data["nodes"][0][field] = value
                if field == "address":
                    value_data["nodes"][0]["ssh"] = "root@" + value
                with self.assertRaises(ValueError): validate_inventory(value_data)

    def test_rejects_bad_fingerprint_and_count(self):
        value = inventory(); value["nodes"][0]["host_key"] = "SHA256:bad"
        with self.assertRaises(ValueError): validate_inventory(value)
        with self.assertRaises(ValueError): validate_inventory({"nodes": []})
        value = inventory(); value["nodes"].append(value["nodes"][0])
        with self.assertRaises(ValueError): validate_inventory(value)

    def test_private_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "secret"; p.write_text("x"); p.chmod(0o600)
            self.assertIsNone(require_private_file(p))
            p.chmod(0o644)
            with self.assertRaises(ValueError): require_private_file(p)

    def test_private_directory_requires_exact_0700(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d) / "credentials"; parent.mkdir(mode=0o700)
            secret = parent / "secret"; secret.write_text("x"); secret.chmod(0o600)
            for mode in (0o1700, 0o2700, 0o4700, 0o755):
                parent.chmod(mode)
                with self.assertRaises(ValueError): require_private_file(secret)
            parent.chmod(0o700)
            require_private_file(secret)

    def test_private_file_rejects_symlink_and_repository_descendant(self):
        with tempfile.TemporaryDirectory() as d:
            root, repo = Path(d), Path(d) / "repo"
            repo.mkdir(mode=0o700)
            secret = root / "secret"; secret.write_text("x"); secret.chmod(0o600)
            link = root / "link"; link.symlink_to(secret)
            with self.assertRaises(ValueError): require_private_file(link)
            with self.assertRaises(ValueError): require_private_file(repo / "x", repo)

    def test_private_file_requires_private_parent_directory(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d) / "credentials"; parent.mkdir(mode=0o700)
            secret = parent / "secret"; secret.write_text("x"); secret.chmod(0o600)
            parent.chmod(0o755)
            with self.assertRaises(ValueError): require_private_file(secret)
            parent.chmod(0o700)
            self.assertIsNone(require_private_file(secret))

    def test_symlinked_tmp_and_var_named_ancestors_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); real = root / "real"; real.mkdir()
            for name in ("tmp", "var"):
                link = root / name; link.symlink_to(real, target_is_directory=True)
                with self.assertRaises(ValueError): require_private_file(link / "secret")

    def test_trusted_readable_ancestor_is_allowed_but_writable_is_not(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "ancestor"; root.mkdir(mode=0o755)
            child = root / "child"; child.mkdir(mode=0o700)
            self.assertEqual(_absolute_no_symlinks(child), Path(os.path.realpath(child)))
            root.chmod(0o775)
            with self.assertRaises(ValueError): _absolute_no_symlinks(child)
class ContextTests(unittest.TestCase):
    def test_new_context_is_fresh_private(self):
        with tempfile.TemporaryDirectory() as d:
            ctx = new_run_context(Path(d), repository=Path(d) / "repo")
            self.assertEqual(stat.S_IMODE(ctx.local_root.stat().st_mode), 0o700)
            self.assertTrue(ctx.remote_root.startswith("/var/lib/hat-qualification/"))
            self.assertNotEqual(ctx.run_id, new_run_context(Path(d)).run_id)

    def test_existing_work_root_must_be_private_directory(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "runs"; root.mkdir(mode=0o700)
            root.chmod(0o755)
            with self.assertRaises(ValueError): new_run_context(root)
            file_path = Path(d) / "file"; file_path.write_text("x")
            with self.assertRaises(ValueError): new_run_context(file_path)

    def test_context_rejects_repository_descendant_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root, repo = Path(d), Path(d) / "repo"
            repo.mkdir(mode=0o700)
            with self.assertRaises(ValueError): new_run_context(repo / "runs", repo)
            link = Path(d) / "link"; link.symlink_to(root)
            with self.assertRaises(ValueError): new_run_context(link)

    def test_context_root_must_be_fresh_exact_id(self):
        ctx = RunContext("bad", Path("/tmp/x"), "/var/lib/hat-qualification/bad")
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/known")):
            with self.assertRaises(ValueError): ensure_remote_root(node(), ctx)

class HostKeyTests(unittest.TestCase):
    def _scan(self, stdout, returncode=0):
        return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")

    def test_missing_key_rejected(self):
        with mock.patch("run.subprocess.run", return_value=self._scan("")):
            with self.assertRaises(RuntimeError): _known_host_fingerprint("a")

    def test_multiple_keys_rejected(self):
        text = "a ssh-ed25519 AAAA\na ssh-ed25519 BBBB\n"
        with mock.patch("run.subprocess.run", return_value=self._scan(text)):
            with self.assertRaises(RuntimeError): _known_host_fingerprint("a")

    def test_scan_failure_rejected(self):
        with mock.patch("run.subprocess.run", return_value=self._scan("", 1)):
            with self.assertRaises(RuntimeError): _known_host_fingerprint("a")

    def test_pinned_directory_rejects_special_mode_bits(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / "pins"; directory.mkdir(mode=0o700)
            for mode in (0o1700, 0o2700, 0o4700):
                directory.chmod(mode)
                with self.assertRaises(ValueError): build_pinned_known_hosts([node()], directory)

    def test_pinned_key_mismatch_and_success(self):
        scan = self._scan("a ssh-ed25519 AAAA\n")
        keygen = self._scan("256 " + FP + " (ED25519)\n")
        with tempfile.TemporaryDirectory() as d, mock.patch("run.subprocess.run", side_effect=[scan, keygen]):
            p = build_pinned_known_hosts([node()], Path(d))
            self.assertEqual(p.read_text(), "a ssh-ed25519 AAAA\n")
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        with tempfile.TemporaryDirectory() as d, mock.patch("run.subprocess.run", side_effect=[scan, self._scan("256 SHA256:" + "B" * 43 + " (ED25519)")]):
            with self.assertRaises(RuntimeError): build_pinned_known_hosts([node()], Path(d))

class TransportTests(unittest.TestCase):
    def test_low_level_transport_rejects_unvalidated_node(self):
        bad = Node("fm1", "root@a", 1, "a", "bad/address", FP, "a")
        with self.assertRaises(ValueError): ssh(bad, ["true"])
        with self.assertRaises(ValueError): scp_to(bad, Path("/tmp/missing"), "/x")

    def test_ssh_options_order_target_and_quote(self):
        n = node()
        with mock.patch("run.subprocess.run") as call, mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/known_hosts")):
            ssh(n, ["printf", "hello; rm -rf /"])
        command = call.call_args.args[0]
        self.assertEqual(command[0], "ssh")
        self.assertLess(command.index("StrictHostKeyChecking=yes"), command.index("--"))
        self.assertEqual(command[-2], n.ssh)
        self.assertEqual(command[-1], "printf 'hello; rm -rf /'")
        self.assertEqual(call.call_args.kwargs["timeout"], 60)

    def test_ssh_requires_pinning_and_nonempty_command(self):
        with self.assertRaises(RuntimeError): ssh(node(), ["true"])
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")):
            with self.assertRaises(ValueError): ssh(node(), [])

    def test_scp_confines_destination_and_uses_options(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "x"; source.write_text("x"); source.chmod(0o600)
            scp_result = subprocess.CompletedProcess([], 0, b"", b"")
            finalize_result = subprocess.CompletedProcess([], 0, b"", b"")
            with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._REMOTE_ROOT", "/var/lib/hat-qualification/r"):
                with mock.patch("run.subprocess.run", return_value=scp_result) as local_scp:
                    with mock.patch("run.ssh", return_value=finalize_result) as remote:
                        scp_to(node(), source, "/var/lib/hat-qualification/r/x")
            command = local_scp.call_args.args[0]
            self.assertEqual(command[0], "scp")
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("UserKnownHostsFile=/tmp/k", command)
            self.assertEqual(command[command.index("--") + 1], str(source.resolve()))
            remote_target = command[-1]
            self.assertRegex(remote_target, r"^root@a:/var/lib/hat-qualification/r/\.x\.hat-copy-[0-9a-f]{32}$")
            finalize = remote.call_args.args[1]
            self.assertEqual(finalize[:2], ["python3", "-c"])
            self.assertIn("O_NOFOLLOW", finalize[2])
            self.assertIn("os.link", finalize[2])
            self.assertIn("follow_symlinks=False", finalize[2])
            temporary = finalize[4]
            destination = finalize[5]
            self.assertTrue(temporary.startswith("/var/lib/hat-qualification/r/"))
            self.assertEqual(destination, "/var/lib/hat-qualification/r/x")
            self.assertEqual(remote.call_count, 1)

    def test_scp_failure_cleans_partial_temporary(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "x"; source.write_text("x")
            failed = subprocess.CompletedProcess([], 7, b"", b"scp failed")
            cleanup = subprocess.CompletedProcess([], 0, b"", b"")
            with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._REMOTE_ROOT", "/var/lib/hat-qualification/r"):
                with mock.patch("run.subprocess.run", return_value=failed) as local_scp:
                    with mock.patch("run.ssh", return_value=cleanup) as remote:
                        with self.assertRaises(subprocess.CalledProcessError):
                            scp_to(node(), source, "/var/lib/hat-qualification/r/x")
            self.assertEqual(local_scp.call_args.args[0][0], "scp")
            self.assertEqual(remote.call_count, 1)
            cleanup_command = remote.call_args.args[1]
            self.assertEqual(cleanup_command[:3], ["rm", "-f", "--"])
            self.assertTrue(cleanup_command[3].startswith("/var/lib/hat-qualification/r/"))

    def test_finalize_failure_cleans_temporary_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "x"; source.write_text("x")
            finalize_failed = subprocess.CompletedProcess([], 1, b"", b"destination exists or symlink")
            cleanup = subprocess.CompletedProcess([], 0, b"", b"")
            with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._REMOTE_ROOT", "/var/lib/hat-qualification/r"):
                with mock.patch("run.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
                    with mock.patch("run.ssh", side_effect=[finalize_failed, cleanup]) as remote:
                        with self.assertRaises(subprocess.CalledProcessError):
                            scp_to(node(), source, "/var/lib/hat-qualification/r/x")
            self.assertEqual(remote.call_count, 2)
            finalize = remote.call_args_list[0].args[1]
            cleanup_command = remote.call_args_list[1].args[1]
            self.assertEqual(finalize[:2], ["python3", "-c"])
            self.assertEqual(cleanup_command[:3], ["rm", "-f", "--"])
            self.assertEqual(cleanup_command[3], finalize[4])

    def test_scp_rejects_traversal_symlink_and_outside_root(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "x"; source.write_text("x")
            with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._REMOTE_ROOT", "/var/lib/hat-qualification/r"):
                with self.assertRaises(RuntimeError): scp_to(node(), source, "/var/lib/hat-qualification/r/../x")
                with self.assertRaises(RuntimeError): scp_to(node(), source, "/tmp/x")
            source.unlink(); source.symlink_to(Path(d) / "other")
            with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._REMOTE_ROOT", "/var/lib/hat-qualification/r"):
                with self.assertRaises(ValueError): scp_to(node(), source, "/var/lib/hat-qualification/r/x")

class RemoteRootTests(unittest.TestCase):
    def setUp(self):
        self.ctx = RunContext("20260907T010203Z-0123456789", Path("/tmp/local"), "/var/lib/hat-qualification/20260907T010203Z-0123456789")
        self.base = subprocess.CompletedProcess([], 0, b"directory 0 0 755 /var/lib/hat-qualification\n")
        self.empty = subprocess.CompletedProcess([], 0, b"")

    def test_creates_and_verifies_root(self):
        root = b"directory 0 0 700 " + self.ctx.remote_root.encode() + b"\n"
        def calls(n, argv, **kw):
            if argv[0] == "stat":
                path = argv[-1]
                if path == self.ctx.remote_root: return subprocess.CompletedProcess([], 0, root)
                if path == "/var/lib/hat-qualification": return subprocess.CompletedProcess([], 0, b"directory 0 0 700 /var/lib/hat-qualification\n")
                return subprocess.CompletedProcess([], 0, ("directory 0 0 755 " + path + "\n").encode())
            if argv[0] == "realpath": return subprocess.CompletedProcess([], 0, (argv[-1] + "\n").encode())
            return self.empty
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run.ssh", side_effect=calls) as call:
            ensure_remote_root(node(), self.ctx)
        self.assertTrue(any(c.args[1][0] == "mkdir" for c in call.call_args_list))

    def test_rejects_untrusted_base(self):
        bad = subprocess.CompletedProcess([], 0, b"symbolic link 0 0 755 /var/lib/hat-qualification\n")
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run.ssh", return_value=bad):
            with self.assertRaises(RuntimeError): ensure_remote_root(node(), self.ctx)

    def test_rejects_wrong_owner_and_mode_base(self):
        from run import _verify_remote_directory
        for metadata in (("directory", 100, 0, 0o700, "/var/lib/hat-qualification"), ("directory", 0, 0, 0o755, "/var/lib/hat-qualification")):
            with mock.patch("run._remote_stat", return_value=metadata), mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")):
                with self.assertRaises(RuntimeError): _verify_remote_directory(node(), "/var/lib/hat-qualification", mode=0o700)

    def test_absent_base_is_bootstrapped_before_root(self):
        root = b"directory 0 0 700 " + self.ctx.remote_root.encode() + b"\n"
        missing = subprocess.CompletedProcess([], 1, b"")
        def calls(n, argv, **kw):
            if argv[0] == "stat" and argv[-1] == "/var/lib/hat-qualification": return missing
            if argv[0] == "stat": return subprocess.CompletedProcess([], 0, root)
            return self.empty
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._verify_remote_directory"), mock.patch("run.ssh", side_effect=calls) as call:
            ensure_remote_root(node(), self.ctx)
        mkdirs = [c.args[1] for c in call.call_args_list if c.args[1][0] == "mkdir"]
        self.assertEqual(mkdirs[0][-1], "/var/lib/hat-qualification")
        self.assertEqual(mkdirs[1][-1], self.ctx.remote_root)

    def test_existing_root_is_rejected_without_mkdir(self):
        existing = subprocess.CompletedProcess([], 1, b"")
        calls = [self.base, existing, subprocess.CompletedProcess([], 0, b"exists")]
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._verify_remote_directory"), mock.patch("run.ssh", side_effect=calls) as call:
            with self.assertRaises(RuntimeError): ensure_remote_root(node(), self.ctx)
        self.assertFalse(any(c.args[1][0] == "mkdir" for c in call.call_args_list))

    def test_failed_verification_removes_new_root(self):
        wrong = b"directory 0 0 755 " + self.ctx.remote_root.encode() + b"\n"
        def calls(n, argv, **kw):
            if argv[0] == "stat": return subprocess.CompletedProcess([], 0, wrong)
            return self.empty
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run._verify_remote_directory"), mock.patch("run.ssh", side_effect=calls) as call:
            with self.assertRaises(RuntimeError): ensure_remote_root(node(), self.ctx)
        self.assertTrue(any(c.args[1][0] == "rmdir" for c in call.call_args_list))

    def test_init_remote_requires_private_inputs(self):
        nodes = [Node("fm1", "root@a", 1, "a", "a", "SHA256:" + "A" * 43, "a"), Node("fm2", "root@b", 2, "b", "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "c", "SHA256:" + "C" * 43, "c")]
        with self.assertRaises(ValueError): init_remote(nodes, self.ctx)

class NodeValidationTests(unittest.TestCase):
    def test_validate_nodes_rechecks_every_field(self):
        from run import _validate_nodes
        valid = [Node("fm1", "root@a", 1, "a", "a", FP, "a"), Node("fm2", "root@b", 2, "b", "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "c", "SHA256:" + "C" * 43, "c")]
        _validate_nodes(valid)
        for field, value in (("name", "bad name"), ("ssh", "hat@a"), ("address", "bad/address"), ("provider_label", "bad label"), ("host_key", "bad"), ("hostname", "bad host"), ("instance_id", 0)):
            bad = list(valid); item = bad[0]; changes = {f: getattr(item, f) for f in ("name", "ssh", "instance_id", "provider_label", "address", "host_key", "hostname")}; changes[field] = value
            bad[0] = Node(**changes)
            with self.assertRaises(ValueError): _validate_nodes(bad)

    def test_preflight_and_init_require_both_private_inputs(self):
        from run import _preflight_impl
        nodes = [Node("fm1", "root@a", 1, "a", "a", FP, "a"), Node("fm2", "root@b", 2, "b", "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "c", "SHA256:" + "C" * 43, "c")]
        ctx = RunContext("20260907T010203Z-0123456789", Path("/tmp/x"), "/var/lib/hat-qualification/20260907T010203Z-0123456789")
        with self.assertRaises(ValueError): _preflight_impl(nodes, ctx, Path("/tmp/e"), inventory_path=Path("/tmp/i"))
        with self.assertRaises(ValueError): init_remote(nodes, ctx, inventory_path=Path("/tmp/i"))

class CLITests(unittest.TestCase):
    def test_init_cli_does_not_reuse_stale_marker(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "runs"; root.mkdir(mode=0o700)
            run_id = "20260907T010203Z-0123456789"
            stale = root / run_id; stale.mkdir(mode=0o700)
            marker = stale / ".preflight-ok"; marker.write_text(run_id + "\n"); marker.chmod(0o600)
            inventory_path = Path(d) / "inventory.json"; inventory_path.write_text(json.dumps(inventory(("fm1", "fm2", "fm3")))); inventory_path.chmod(0o600)
            env_path = Path(d) / "env"; env_path.write_text("export LINODE_TOKEN=x\nexport HAT_FM1_LINODE_ID=1\nexport HAT_FM2_LINODE_ID=2\nexport HAT_FM3_LINODE_ID=3\n"); env_path.chmod(0o600)
            with self.assertRaises(ValueError):
                main(["init-remote", "--inventory", str(inventory_path), "--linode-env", str(env_path), "--work-root", str(root)])

    def test_cli_requires_explicit_credentials(self):
        with self.assertRaises(SystemExit): main(["init-remote", "--work-root", "/tmp/hat-m1"])

class FactsTests(unittest.TestCase):
    def test_accepts_exact_boundary_facts(self):
        _require_facts(node(), facts())

    def test_hostname_must_be_exact(self):
        for value in ("b", "a.example", "a\nother"):
            bad = facts(value)
            with self.assertRaises(RuntimeError): _require_facts(node(), bad)

    def test_release_is_anchored(self):
        for value in ("ID=ubuntu-old\nVERSION_ID=24.04", "XID=ubuntu\nVERSION_ID=24.04", "ID=ubuntu\nVERSION_ID=24.040"):
            bad = facts(); bad["release"] = value
            with self.assertRaises(RuntimeError): _require_facts(node(), bad)

    def test_time_and_tls_are_anchored(self):
        for field, value in (("time_sync", "NTPSynchronized=yes\nother=no"), ("time_sync", "ntpsynchronized=yes\n"), ("outbound_tls", "HAT_M1_TLS_OK extra")):
            bad = facts(); bad[field] = value
            with self.assertRaises(RuntimeError): _require_facts(node(), bad)

    def test_disk_requires_exact_root_schema_and_numeric_values(self):
        for value in (
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1 1 1 10% / /extra\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x one 1 1 10% /\n",
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/x 1 2 1 10% /\n",
        ):
            bad = facts(); bad["disk"] = value
            with self.assertRaises(RuntimeError): _require_facts(node(), bad)

    def test_resources_are_strict(self):
        for field, value in (("cpu", "0"), ("memory", "MemTotal: 100 kB\n"), ("disk", "Filesystem x\n/dev/x 1 1 1 91% /\n")):
            bad = facts(); bad[field] = value
            with self.assertRaises(RuntimeError): _require_facts(node(), bad)

    def test_missing_fact_is_rejected(self):
        bad = facts(); del bad["cpu"]
        with self.assertRaises(RuntimeError): _require_facts(node(), bad)

class EnvTests(unittest.TestCase):
    def write_env(self, directory, text):
        p = Path(directory) / "env"; p.write_text(text); p.chmod(0o600); return p

    def test_strict_env_and_id_mapping_without_token(self):
        text = "export LINODE_TOKEN='do-not-return'\nexport HAT_FM1_LINODE_ID=11\nexport HAT_FM2_LINODE_ID=22\nexport HAT_FM3_LINODE_ID=33\n"
        with tempfile.TemporaryDirectory() as d:
            result = load_linode_env(self.write_env(d, text), [Node("fm1", "root@one", 11, "one", "one", FP, "one"), Node("fm2", "root@two", 22, "two", "two", FP, "two"), Node("fm3", "root@three", 33, "three", "three", FP, "three")])
        self.assertEqual(result, {"HAT_FM1_LINODE_ID": 11, "HAT_FM2_LINODE_ID": 22, "HAT_FM3_LINODE_ID": 33})
        self.assertNotIn("LINODE_TOKEN", result)

    def test_env_rejects_missing_duplicate_unknown_and_mismatch(self):
        good = "export LINODE_TOKEN=x\nexport HAT_FM1_LINODE_ID=1\nexport HAT_FM2_LINODE_ID=2\nexport HAT_FM3_LINODE_ID=3\n"
        with tempfile.TemporaryDirectory() as d:
            for text in (good.replace("HAT_FM3_LINODE_ID=3", "HAT_FM2_LINODE_ID=3"), good.replace("export LINODE_TOKEN=x\n", "export OTHER=x\n"), good + "\n"):
                with self.assertRaises(ValueError): load_linode_env(self.write_env(d, text))
            wrong = [Node("fm1", "root@one", 9, "one", "one", FP, "one"), Node("fm2", "root@two", 2, "two", "two", FP, "two"), Node("fm3", "root@three", 3, "three", "three", FP, "three")]
            with self.assertRaises(ValueError): load_linode_env(self.write_env(d, good), wrong)

class PreflightEvidenceTests(unittest.TestCase):
    def test_preflight_rejects_manually_supplied_local_context(self):
        from run import _preflight_impl
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d) / "repo"; repo.mkdir(mode=0o700)
            bad = RunContext("20260907T010203Z-0123456789", repo, "/var/lib/hat-qualification/20260907T010203Z-0123456789")
            with self.assertRaises(ValueError): _preflight_impl([], bad, repo / "evidence.jsonl", repo)

    def test_init_rejects_manual_context_and_evidence_escape(self):
        from run import init_remote
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "root"; root.mkdir(mode=0o700)
            bad = RunContext("20260907T010203Z-0123456789", root, "/var/lib/hat-qualification/20260907T010203Z-0123456789")
            nodes = [Node("fm1", "root@a", 1, "a", "a", "SHA256:" + "A" * 43, "a"), Node("fm2", "root@b", 2, "b", "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "c", "SHA256:" + "C" * 43, "c")]
            with self.assertRaises(ValueError): init_remote(nodes, bad, root / "evidence.jsonl")
            ctx = new_run_context(Path(d))
            marker = ctx.local_root / ".preflight-ok"; marker.write_text(ctx.run_id + "\\n"); marker.chmod(0o600)
            with self.assertRaises(ValueError): init_remote(nodes, ctx, Path(d) / "outside.jsonl")
            marker.unlink()
            with mock.patch("run.build_pinned_known_hosts", return_value=Path(d) / "known"):
                with self.assertRaises(ValueError): init_remote(nodes, ctx, ctx.local_root / "evidence.jsonl")

    def test_evidence_rejects_repository_descendant_and_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            root, repo = Path(d), Path(d) / "repo"; repo.mkdir(mode=0o700)
            with self.assertRaises(ValueError): append_evidence(repo / "evidence", {"x": 1}, repo)
            target = root / "real"; target.mkdir(mode=0o700)
            link = root / "link"; link.symlink_to(target)
            with self.assertRaises(ValueError): append_evidence(link / "evidence", {"x": 1})

    def test_redacts_sensitive_values_and_fsyncs_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "evidence.jsonl"
            append_evidence(p, {"password": "secret", "nested": {"token": "x"}})
            data = p.read_text()
            self.assertNotIn("secret", data); self.assertNotIn('"x"', data)
            self.assertEqual(json.loads(data)["password"], "[REDACTED]")

    def test_loaded_secret_is_redacted_inside_ordinary_values(self):
        secret = "m1-test-token-unique-8f2b"
        env_text = f"export LINODE_TOKEN='{secret}'\nexport HAT_FM1_LINODE_ID=1\nexport HAT_FM2_LINODE_ID=2\nexport HAT_FM3_LINODE_ID=3\n"
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / "env"
            env.write_text(env_text); env.chmod(0o600)
            self.assertNotIn("LINODE_TOKEN", load_linode_env(env))
            value = redact({"message": f"before-{secret}-after", "ordinary": secret})
        self.assertEqual(value["message"], "before-[REDACTED]-after")
        self.assertEqual(value["ordinary"], "[REDACTED]")
        self.assertNotIn(secret, json.dumps(value))

    def test_evidence_requires_private_directory(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d) / "evidence"; directory.mkdir(mode=0o700)
            path = directory / "events.jsonl"
            for mode in (0o1700, 0o2700, 0o4700, 0o755):
                directory.chmod(mode)
                with self.assertRaises(ValueError): append_evidence(path, {"ok": True})
            directory.chmod(0o700)
            append_evidence(path, {"ok": True})
            path.chmod(0o644)
            with self.assertRaises(ValueError): append_evidence(path, {"ok": True})
            path.chmod(0o1600)
            with self.assertRaises(ValueError): append_evidence(path, {"ok": True})

    def test_init_rejects_replaced_credentials_without_mutation(self):
        from run import _write_preflight_handoff
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); inventory_path = root / "inventory"; env = root / "env"
            inventory_path.write_text("inventory"); inventory_path.chmod(0o600)
            env.write_text("env"); env.chmod(0o600)
            ctx = new_run_context(root)
            (ctx.local_root / ".preflight-ok").write_text(ctx.run_id + "\n"); (ctx.local_root / ".preflight-ok").chmod(0o600)
            _write_preflight_handoff(ctx, inventory_path, env)
            inventory_path.write_text("replacement")
            nodes = [Node("fm1", "root@a", 1, "a", "a", "SHA256:" + "A" * 43, "a"), Node("fm2", "root@b", 2, "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "SHA256:" + "C" * 43, "c")]
            with mock.patch("run._validate_prerequisites"), mock.patch("run.build_pinned_known_hosts") as pins, mock.patch("run.ensure_remote_root") as mutate:
                with self.assertRaises(ValueError): init_remote(nodes, ctx, ctx.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)
            mutate.assert_not_called()

    def test_init_consumes_handoff_before_remote_mutation(self):
        from run import _write_preflight_handoff
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); inventory_path = root / "inventory"; env = root / "env"
            inventory_path.write_text("inventory"); inventory_path.chmod(0o600)
            env.write_text("env"); env.chmod(0o600)
            ctx = new_run_context(root)
            (ctx.local_root / ".preflight-ok").write_text(ctx.run_id + "\n"); (ctx.local_root / ".preflight-ok").chmod(0o600)
            _write_preflight_handoff(ctx, inventory_path, env)
            nodes = [Node("fm1", "root@a", 1, "a", "a", "SHA256:" + "A" * 43, "a"), Node("fm2", "root@b", 2, "b", "b", "SHA256:" + "B" * 43, "b"), Node("fm3", "root@c", 3, "c", "c", "SHA256:" + "C" * 43, "c")]
            with mock.patch("run._validate_prerequisites"), mock.patch("run.build_pinned_known_hosts", return_value=root / "known"), mock.patch("run.ensure_remote_root", side_effect=RuntimeError("mutation")) as mutate:
                with self.assertRaises(RuntimeError): init_remote(nodes, ctx, ctx.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)
            self.assertFalse((ctx.local_root / ".preflight-handoff").exists())
            self.assertTrue((ctx.local_root / ".preflight-handoff.used").exists())
            self.assertEqual(mutate.call_count, 1)
            with self.assertRaises(ValueError): init_remote(nodes, ctx, ctx.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)

if __name__ == "__main__": unittest.main()
