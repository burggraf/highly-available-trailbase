import datetime
import hashlib
import io
import json
import os
import threading
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from run import (
    Node, RunContext, _FINGERPRINT, _require_facts, _known_host_fingerprint, _remote_stat, _verify_remote_directory, _verify_reboot,
    invoke_fence, validate_fence_evidence, promotion_allowed,
    append_evidence, build_pinned_known_hosts, ensure_remote_root, init_remote,
    load_inventory, load_linode_env, new_run_context, require_private_file,
    redact, scp_to, ssh, storage, validate_inventory, _absolute_no_symlinks,
    main, StorageStatus, write_latest_storage_evidence_pointer,
    Artifact, artifact_for, confined_remote_path, extract_verified_artifact,
    mask_writer_services, missing_packages, published_checksum,
    validate_binary_version, validate_release_metadata, _install_required_packages,
    _binary_version_evidence, _copy_from_node, _run_m0_linux_parity,
    _validate_m0_aggregate, _validate_m0_log_archive, _validate_provision_summary,
    _validate_post_reboot_summary, _provision_workflow, provision, REMOTE_PROVISION_TIMEOUT,
    _M0_COLLECT_SCRIPT, _download_public, _safe_archive_member,
)

FP = "SHA256:" + "A" * 43


class FenceContractTests(unittest.TestCase):
    def target(self):
        return {"cluster": "test", "node": "old", "boot": "boot-1"}

    def fake(self, directory, payload, *, exit_code=0, delay=0):
        path = directory / "fake-fence"
        path.write_text("#!/usr/bin/env python3\nimport json,sys,time\n"
                        f"time.sleep({delay})\n"
                        f"print({json.dumps(json.dumps(payload))})\n"
                        f"sys.exit({exit_code})\n")
        path.chmod(0o700)
        return path

    def evidence(self, target, *, action="power-off", state="offline"):
        completed = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
        requested = completed - datetime.timedelta(seconds=1)
        stamp = lambda value: value.isoformat().replace("+00:00", "Z")
        return {"action": action, "target": target, "request": {"id": "req-1", "time": stamp(requested)},
                "completion": {"time": stamp(completed)}, "state": state,
                "observations": [{"time": stamp(completed), "state": state}]}

    def test_only_fresh_exact_completed_isolation_promotes(self):
        target = self.target()
        valid = self.evidence(target)
        self.assertTrue(validate_fence_evidence(valid, target, "power-off"))
        self.assertTrue(promotion_allowed(valid, target))
        stale = self.evidence(target)
        stale["completion"]["time"] = "2000-01-01T00:00:01Z"
        stale["observations"][0]["time"] = "2000-01-01T00:00:01Z"
        self.assertFalse(promotion_allowed(stale, target))
        before_completion = self.evidence(target)
        before_completion["observations"][0]["time"] = "2000-01-01T00:00:00Z"
        before_completion["completion"]["time"] = "2000-01-01T00:00:01Z"
        self.assertFalse(validate_fence_evidence(before_completion, target, "power-off"))
        for bad in (self.evidence(target, state="running"), self.evidence({**target, "boot": "new"}),
                    {**valid, "completion": None}, {**valid, "request": {"id": "req-1"}}):
            self.assertFalse(promotion_allowed(bad, target))

    def test_future_observation_and_invalid_encoding_fail_closed(self):
        target = self.target()
        future = self.evidence(target)
        future_time = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
        future["observations"][0]["time"] = future_time
        self.assertFalse(validate_fence_evidence(future, target, "power-off"))
        with tempfile.TemporaryDirectory() as parent:
            path = Path(parent) / "bad-encoding"
            path.write_text("#!/bin/sh\nprintf '\\\\377'")
            path.chmod(0o700)
            result = invoke_fence(path, "power-off", target)
            self.assertFalse(result["valid"])

    def test_invoke_rejects_non_json_target(self):
        with tempfile.TemporaryDirectory() as parent:
            path = self.fake(Path(parent), self.evidence(self.target()))
            result = invoke_fence(path, "power-off", {"node": object()})
            self.assertFalse(result["valid"])

    def test_invoke_rejects_malformed_failed_timeout_and_duplicate(self):
        with tempfile.TemporaryDirectory() as parent:
            directory, target = Path(parent), self.target()
            cases = [("malformed", "not-json", 0, 0), ("failed", self.evidence(target), 1, 0),
                     ("timeout", self.evidence(target), 0, 1), ("no-op", self.evidence(target, state="running"), 0, 0),
                     ("mismatch", self.evidence({**target, "node": "other"}), 0, 0),
                     ("delayed", self.evidence(target), 0, 0.1)]
            for _, payload, exit_code, delay in cases:
                path = directory / "fake"
                if isinstance(payload, str):
                    path.write_text("#!/bin/sh\nprintf 'not-json\\n'")
                else:
                    path = self.fake(directory, payload, exit_code=exit_code, delay=delay)
                path.chmod(0o700)
                result = invoke_fence(path, "power-off", target, timeout=0.05 if delay else 2)
                expected = payload != "not-json" and exit_code == 0 and delay == 0 and payload.get("target") == target and payload.get("state") == "offline"
                self.assertEqual(result["valid"], expected)
            already_offline = self.evidence(target)
            self.assertTrue(promotion_allowed(already_offline, target))
            duplicate = self.evidence(target)
            duplicate["observations"].append(duplicate["observations"][0])
            self.assertFalse(promotion_allowed(duplicate, target))

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

    def test_linux_style_sticky_ancestor_is_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            sticky = Path(d) / "tmp"; sticky.mkdir(mode=0o700); sticky.chmod(0o1777)
            work = sticky / "hat"; work.mkdir(mode=0o700)
            self.assertEqual(_absolute_no_symlinks(work), Path(os.path.realpath(work)))
            context = new_run_context(sticky / "runs")
            self.assertTrue(context.local_root.is_dir())
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
            with mock.patch("run.subprocess.run") as execute:
                ssh(node(), ["true"], timeout=900)
            self.assertEqual(execute.call_args.kwargs["timeout"], 900)

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
    def test_remote_stat_parses_multiword_regular_file_kind(self):
        result = subprocess.CompletedProcess([], 0, b"regular file\t0\t0\t600\t/safe/file\n", b"")
        with mock.patch("run.ssh", return_value=result):
            self.assertEqual(_remote_stat(node(), "/safe/file"), ("regular file", 0, 0, 0o600, "/safe/file"))

    def test_reboot_returns_new_boot_identity_for_evidence(self):
        old = "01234567-89ab-cdef-0123-456789abcdef"
        new = "abcdef01-2345-6789-abcd-ef0123456789"
        responses = [subprocess.CompletedProcess([], 0, b"", b""),
                     subprocess.CompletedProcess([], 0, (new + "\n").encode(), b""),
                     subprocess.CompletedProcess([], 0, b"a\n", b"")]
        responses += [subprocess.CompletedProcess([], 0, b"masked\n", b""),
                      subprocess.CompletedProcess([], 3, b"inactive\n", b"")] * 2
        with mock.patch("run.ssh", side_effect=responses), mock.patch("run.time.sleep"):
            self.assertEqual(_verify_reboot(node("a"), old), new)

    def test_reboot_query_error_is_not_treated_as_inactive(self):
        old = "01234567-89ab-cdef-0123-456789abcdef"
        new = "abcdef01-2345-6789-abcd-ef0123456789"
        responses = [
            subprocess.CompletedProcess([], 0, b"", b""),
            subprocess.CompletedProcess([], 0, (new + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, b"a\n", b""),
            subprocess.CompletedProcess([], 0, b"masked\n", b""),
            subprocess.CompletedProcess([], 1, b"", b"query failed"),
        ]
        with mock.patch("run.ssh", side_effect=responses), mock.patch("run.time.sleep"):
            with self.assertRaises(RuntimeError):
                _verify_reboot(node("a"), old)

    def test_remote_realpath_retries_transient_transport_failure(self):
        failed = subprocess.CompletedProcess([], 255, b"", b"transient")
        passed = subprocess.CompletedProcess([], 0, b"/safe\n", b"")
        with mock.patch("run._remote_stat", return_value=("directory", 0, 0, 0o700, "/safe")), \
             mock.patch("run.ssh", side_effect=[failed, passed]) as transport, mock.patch("run.time.sleep"):
            _verify_remote_directory(node(), "/safe", mode=0o700)
        self.assertEqual(transport.call_count, 2)

    def setUp(self):
        self.ctx = RunContext("20260907T010203Z-0123456789", Path("/tmp/local"), "/var/lib/hat-qualification/20260907T010203Z-0123456789")
        self.base = subprocess.CompletedProcess([], 0, b"directory\t0\t0\t755\t/var/lib/hat-qualification\n")
        self.empty = subprocess.CompletedProcess([], 0, b"")

    def test_creates_and_verifies_root(self):
        root = b"directory\t0\t0\t700\t" + self.ctx.remote_root.encode() + b"\n"
        def calls(n, argv, **kw):
            if argv[0] == "stat":
                path = argv[-1]
                if path == self.ctx.remote_root: return subprocess.CompletedProcess([], 0, root)
                if path == "/var/lib/hat-qualification": return subprocess.CompletedProcess([], 0, b"directory\t0\t0\t700\t/var/lib/hat-qualification\n")
                return subprocess.CompletedProcess([], 0, ("directory\t0\t0\t755\t" + path + "\n").encode())
            if argv[0] == "realpath": return subprocess.CompletedProcess([], 0, (argv[-1] + "\n").encode())
            return self.empty
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run.ssh", side_effect=calls) as call:
            ensure_remote_root(node(), self.ctx)
        self.assertTrue(any(c.args[1][0] == "mkdir" for c in call.call_args_list))

    def test_rejects_untrusted_base(self):
        bad = subprocess.CompletedProcess([], 0, b"symbolic link\t0\t0\t755\t/var/lib/hat-qualification\n")
        with mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")), mock.patch("run.ssh", return_value=bad):
            with self.assertRaises(RuntimeError): ensure_remote_root(node(), self.ctx)

    def test_rejects_wrong_owner_and_mode_base(self):
        from run import _verify_remote_directory
        for metadata in (("directory", 100, 0, 0o700, "/var/lib/hat-qualification"), ("directory", 0, 0, 0o755, "/var/lib/hat-qualification")):
            with mock.patch("run._remote_stat", return_value=metadata), mock.patch("run._SSH_KNOWN_HOSTS", Path("/tmp/k")):
                with self.assertRaises(RuntimeError): _verify_remote_directory(node(), "/var/lib/hat-qualification", mode=0o700)

    def test_absent_base_is_bootstrapped_before_root(self):
        root = b"directory\t0\t0\t700\t" + self.ctx.remote_root.encode() + b"\n"
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
        wrong = b"directory\t0\t0\t755\t" + self.ctx.remote_root.encode() + b"\n"
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
    def _fence_inventory(self, directory):
        path = directory / "inventory.json"
        path.write_text(json.dumps(inventory(("fm1", "fm2", "fm3"))))
        path.chmod(0o600)
        return path

    def _fence_command(self, directory, failing=False, raising=False):
        path = directory / "private-fence"
        body = """#!/usr/bin/env python3
import datetime,json,sys
if %s:
    raise RuntimeError('private failure')
target=json.load(open(sys.argv[2]))
now=datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
stamp=lambda x:x.isoformat().replace('+00:00','Z')
print(json.dumps({'action':sys.argv[1],'target':target,'request':{'id':'request-1','time':stamp(now-datetime.timedelta(seconds=1))},'completion':{'time':stamp(now)},'state':'running','observations':[{'time':stamp(now),'state':'running'}]}))
sys.exit(1 if %s else 0)
""" % (str(raising), str(failing))
        path.write_text(body); path.chmod(0o700)
        return path

    def test_fence_cli_records_three_sanitized_successes_in_fresh_root_and_pointer(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"HOME": d}):
            root = Path(d) / "work"; inventory_path = self._fence_inventory(Path(d))
            command = self._fence_command(Path(d))
            self.assertEqual(main(["fence-inspect", "--inventory", str(inventory_path), "--fence-command", str(command), "--work-root", str(root)]), 0)
            runs = list(root.iterdir()); self.assertEqual(len(runs), 1)
            evidence = runs[0] / "evidence.jsonl"
            events = [json.loads(line) for line in evidence.read_text().splitlines()]
            calls = [event for event in events if event.get("operation") == "fence-inspect"]
            self.assertEqual(len(calls), 3)
            self.assertTrue(all(event["valid"] and event["target_match"] and event["result"] == "PASS" for event in calls))
            self.assertTrue(all(set(("action", "target_sha256", "valid", "request", "completion", "state", "observations", "result")) <= event.keys() for event in calls))
            self.assertEqual(events[-1]["result"], "PASS")
            pointer = Path(d) / ".config" / "hat" / "latest-fence-evidence"
            self.assertEqual(pointer.read_text(), str(evidence.resolve()) + "\n")
            self.assertEqual(stat.S_IMODE(pointer.stat().st_mode), 0o600)
            self.assertNotIn("LINODE_TOKEN", evidence.read_text())

    def test_fence_cli_preserves_partial_failure_and_exception_as_no_go(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"HOME": d}):
            root = Path(d) / "work"; inventory_path = self._fence_inventory(Path(d))
            command = self._fence_command(Path(d), failing=True)
            self.assertEqual(main(["fence-inspect", "--inventory", str(inventory_path), "--fence-command", str(command), "--work-root", str(root)]), 2)
            evidence = next(root.iterdir()) / "evidence.jsonl"
            events = [json.loads(line) for line in evidence.read_text().splitlines()]
            self.assertEqual(len([event for event in events if event.get("operation") == "fence-inspect"]), 3)
            self.assertEqual(events[-1]["result"], "NO-GO")
            self.assertTrue(all(event["result"] == "NO-GO" for event in events if event.get("operation") == "fence-inspect"))
            self.assertTrue((Path(d) / ".config" / "hat" / "latest-fence-evidence").is_file())

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
        with self.assertRaises(SystemExit):
            main(["init-remote", "--work-root", "/tmp/hat-m1"])
        with self.assertRaises(SystemExit):
            main(["provision", "--work-root", "/tmp/hat-m1", "--inventory", "/private/inventory",
                  "--linode-env", "/private/env"])

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
    def _preflight_inputs(self, root):
        nodes = validate_inventory(inventory(("fm1", "fm2", "fm3")))
        inventory_path = root / "inventory.json"
        inventory_path.write_text(json.dumps(inventory(("fm1", "fm2", "fm3"))))
        inventory_path.chmod(0o600)
        env = root / "linode.env"
        env.write_text("export LINODE_TOKEN='orchestration-test-token'\nexport HAT_FM1_LINODE_ID=1\nexport HAT_FM2_LINODE_ID=2\nexport HAT_FM3_LINODE_ID=3\n")
        env.chmod(0o600)
        return nodes, inventory_path, env

    def _run_preflight_transport(self, nodes, outputs_by_node, failure=None):
        labels = ["hostname", "boot_id", "release", "cpu", "memory", "disk", "time_sync", "outbound_tls"]
        expected = ["hostname", "cat /proc/sys/kernel/random/boot_id", "cat /etc/os-release", "nproc", "cat /proc/meminfo", "df -P /", "timedatectl show -p NTPSynchronized", "curl --fail --silent --show-error -o /dev/null -w HAT_M1_TLS_OK https://example.com/"]
        calls = []
        def transport(argv, **kwargs):
            calls.append(argv)
            target = argv[-2]
            index = len(calls) - 1
            node_index, command_index = divmod(index, len(labels))
            if failure == (node_index, command_index):
                return subprocess.CompletedProcess(argv, 1, b"", b"failed")
            command = argv[-1]
            self.assertEqual(command, expected[command_index])
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("UserKnownHostsFile=", " ".join(argv))
            return subprocess.CompletedProcess(argv, 0, outputs_by_node[target][labels[command_index]], b"")
        return calls, transport

    def test_preflight_checks_all_nodes_read_only_and_handoffs(self):
        from run import preflight
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); nodes, inventory_path, env = self._preflight_inputs(root)
            context = new_run_context(root / "runs")
            outputs = {node.ssh: facts(node.hostname) for node in nodes}
            calls, transport = self._run_preflight_transport(nodes, outputs)
            with mock.patch("run.build_pinned_known_hosts", return_value=root / "known_hosts"), mock.patch("run.subprocess.run", side_effect=transport):
                preflight(nodes, context, context.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)
            self.assertEqual(len(calls), 24)
            self.assertEqual([call[-2] for call in calls], [node.ssh for node in nodes for _ in range(8)])
            self.assertFalse(any(call[-1].startswith(prefix) for call in calls for prefix in ("mkdir", "rm", "mv", "touch", "chmod", "systemctl")))
            self.assertTrue((context.local_root / ".preflight-ok").is_file())
            self.assertTrue((context.local_root / ".preflight-handoff").is_file())
            self.assertEqual(len((context.local_root / "evidence.jsonl").read_text().splitlines()), 3)
            import run
            self.assertIsNone(run._SSH_KNOWN_HOSTS)
            self.assertIsNone(run._REMOTE_ROOT)

    def test_preflight_failure_aborts_later_nodes_and_creates_no_handoff(self):
        from run import preflight
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); nodes, inventory_path, env = self._preflight_inputs(root)
            context = new_run_context(root / "runs")
            outputs = {node.ssh: facts(node.hostname) for node in nodes}
            calls, transport = self._run_preflight_transport(nodes, outputs, failure=(1, 0))
            with mock.patch("run.build_pinned_known_hosts", return_value=root / "known_hosts"), mock.patch("run.subprocess.run", side_effect=transport):
                with self.assertRaises(RuntimeError):
                    preflight(nodes, context, context.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)
            self.assertEqual(len(calls), 9)
            self.assertEqual({call[-2] for call in calls}, {nodes[0].ssh, nodes[1].ssh})
            self.assertFalse((context.local_root / ".preflight-ok").exists())
            self.assertFalse((context.local_root / ".preflight-handoff").exists())
            import run
            self.assertIsNone(run._SSH_KNOWN_HOSTS)
            self.assertIsNone(run._REMOTE_ROOT)

    def test_bad_fact_aborts_before_later_node_activity(self):
        from run import preflight
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); nodes, inventory_path, env = self._preflight_inputs(root)
            context = new_run_context(root / "runs")
            outputs = {node.ssh: facts(node.hostname) for node in nodes}
            outputs[nodes[0].ssh] = facts("wrong-host")
            calls, transport = self._run_preflight_transport(nodes, outputs)
            with mock.patch("run.build_pinned_known_hosts", return_value=root / "known_hosts"), mock.patch("run.subprocess.run", side_effect=transport):
                with self.assertRaises(RuntimeError):
                    preflight(nodes, context, context.local_root / "evidence.jsonl", inventory_path=inventory_path, linode_env=env)
            self.assertEqual(len(calls), 8)
            self.assertTrue(all(call[-2] == nodes[0].ssh for call in calls))
            self.assertFalse((context.local_root / ".preflight-ok").exists())
            self.assertFalse((context.local_root / ".preflight-handoff").exists())

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

    def test_marker_and_handoff_reject_special_permission_bits(self):
        from run import _consume_preflight_handoff, _require_preflight_marker, _write_preflight_handoff
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); inventory_path = root / "inventory"; env = root / "env"
            inventory_path.write_text("inventory"); inventory_path.chmod(0o600)
            env.write_text("env"); env.chmod(0o600)
            context = new_run_context(root / "runs")
            marker = context.local_root / ".preflight-ok"
            marker.write_text(context.run_id + "\n"); marker.chmod(0o1600)
            with self.assertRaises(ValueError): _require_preflight_marker(context)
            marker.chmod(0o600)
            _write_preflight_handoff(context, inventory_path, env)
            handoff = context.local_root / ".preflight-handoff"; handoff.chmod(0o1600)
            with self.assertRaises(ValueError): _consume_preflight_handoff(context, inventory_path, env)

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

class _StorageClient:
    def __init__(self, broken_stale_delete=False, discard_unknown=False):
        self.objects = {}
        self.broken_stale_delete = broken_stale_delete
        self.discard_unknown = discard_unknown
        self.lock = threading.Lock()

    @staticmethod
    def _etag(body): return '"' + hashlib.md5(body).hexdigest() + '"'
    def _result(self, status, body=b"", etag=""):
        headers = {"x-amz-request-id": "test-request"}
        if etag: headers["ETag"] = etag
        return status, headers, body
    def put(self, key, body, *, etag=None, if_none_match=False, headers=None):
        with self.lock:
            current = self.objects.get(key)
            if if_none_match and current is not None: return self._result(412)
            if etag is not None and (current is None or current[1] != etag): return self._result(412)
            value = (body, self._etag(body)); self.objects[key] = value
            return self._result(200, etag=value[1])
    def head(self, key):
        value = self.objects.get(key)
        return self._result(404) if value is None else self._result(200, etag=value[1])
    def get(self, key):
        value = self.objects.get(key)
        return self._result(404) if value is None else self._result(200, value[0], value[1])
    def delete(self, key, *, etag=None):
        with self.lock:
            current = self.objects.get(key)
            if current is None: return self._result(404)
            if etag is not None and current[1] != etag:
                return self._result(204 if self.broken_stale_delete else 412)
            del self.objects[key]
            return self._result(204)
    def list(self, prefix=""):
        keys = sorted(key for key in self.objects if key.startswith(prefix))
        body = ("<ListBucketResult>" + "".join(f"<Contents><Key>{key}</Key></Contents>" for key in keys) + "</ListBucketResult>").encode()
        return self._result(200, body)
    def put_discarded(self, key, body, *, etag=None, if_none_match=False):
        from s3 import Reconciliation
        if not self.discard_unknown: self.put(key, body, etag=etag, if_none_match=if_none_match)
        return Reconciliation.UNKNOWN
    def reconcile_put_detailed(self, key, body, etag=None):
        from s3 import Reconciliation, ReconciliationProbe, ReconciliationResult
        head = self.head(key); get = self.get(key)
        probes = tuple(ReconciliationProbe.from_response(method, response) for method, response in (("HEAD", head), ("GET", get)))
        outcome = Reconciliation.DISCARDED if head[0] == 404 else (Reconciliation.COMMITTED if get[0] == 200 and (etag is None or get[1]["ETag"] == etag) and get[2] == body else Reconciliation.UNKNOWN)
        return ReconciliationResult(outcome, probes)


class StorageQualificationTests(unittest.TestCase):
    def run_storage(self, client, cleanup=False):
        events = []
        context = mock.Mock(run_id="20260907T000000Z-0123456789")
        with mock.patch("s3.client_from_env", return_value=client), mock.patch("run.append_evidence", side_effect=lambda path, event, repository=None: events.append(event)):
            status = storage(context=context, evidence=Path("/private/evidence"), s3_env=Path("/private/env"), cleanup=cleanup)
        return status, events

    def test_storage_pass_records_complete_matrix(self):
        status, events = self.run_storage(_StorageClient())
        self.assertIs(status, StorageStatus.PASS)
        operations = {event.get("operation") for event in events}
        self.assertTrue({"put-unconditional", "head-unconditional", "get-unconditional", "delete-unconditional", "head-after-delete-unconditional", "put-replace-missing", "delete-current", "race-create-final", "race-create-lineage", "race-replace-final", "race-replace-lineage", "list", "discarded-response-reconciliation", "storage-result"}.issubset(operations))
        unconditional = {event["operation"]: event for event in events if event.get("operation", "").endswith("-unconditional")}
        self.assertEqual(unconditional["get-unconditional"]["request_payload_sha256"], hashlib.sha256(b"ordinary").hexdigest())
        self.assertEqual(unconditional["get-unconditional"]["response_payload_sha256"], hashlib.sha256(b"ordinary").hexdigest())
        self.assertEqual(unconditional["head-unconditional"]["etag"], unconditional["get-unconditional"]["etag"])
        self.assertEqual(unconditional["put-unconditional"]["method"], "PUT")
        self.assertEqual(unconditional["put-unconditional"]["key"], "qualification/20260907T000000Z-0123456789/control/unconditional")
        self.assertEqual(next(event for event in events if event["operation"] == "put-create")["request_headers"], {"If-None-Match": "*"})
        self.assertEqual(next(event for event in events if event["operation"] == "delete-stale-refused")["request_headers"], {"If-Match": '"' + hashlib.md5(b"old").hexdigest() + '"'})
        self.assertTrue(all(event.get("method") and event.get("key") for event in events if "status" in event))
        result = events[-1]
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["failures"], [])

    def test_storage_preserves_fresh_prefix_by_default_and_cleanup_is_opt_in(self):
        client = _StorageClient()
        status, _ = self.run_storage(client)
        self.assertIs(status, StorageStatus.PASS)
        self.assertTrue(client.objects)
        client = _StorageClient()
        events = []
        context = mock.Mock(run_id="20260907T000000Z-0123456789")
        with mock.patch("s3.client_from_env", return_value=client), mock.patch("run.append_evidence", side_effect=lambda path, event, repository=None: events.append(event)):
            status = storage(context=context, evidence=Path("/private/evidence"), s3_env=Path("/private/env"), cleanup=True)
        self.assertIs(status, StorageStatus.PASS)
        self.assertFalse(client.objects)

    def test_cleanup_never_deletes_after_no_go(self):
        client = _StorageClient(broken_stale_delete=True)
        status, events = self.run_storage(client, cleanup=True)
        self.assertIs(status, StorageStatus.NO_GO)
        self.assertTrue(client.objects)
        self.assertEqual(events[-1]["result"], "NO-GO")

    def test_latest_storage_pointer_is_private_and_contains_only_evidence_path(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("run.Path.home", return_value=Path(d)):
            evidence = Path(d) / "runs" / "evidence.jsonl"
            evidence.parent.mkdir(mode=0o700)
            write_latest_storage_evidence_pointer(evidence)
            pointer = Path(d) / ".config" / "hat" / "m1-latest-storage-evidence"
            self.assertEqual(pointer.read_text(), str(evidence.resolve()) + "\n")
            self.assertEqual(stat.S_IMODE(pointer.stat().st_mode), 0o600)
            self.assertNotIn("secret", pointer.read_text())

    def test_storage_passes_when_discarded_request_reconciles_absent(self):
        status, events = self.run_storage(_StorageClient(discard_unknown=True))
        self.assertIs(status, StorageStatus.PASS)
        reconciliation = next(event for event in events if event.get("operation") == "discarded-response-reconciliation")
        self.assertEqual(reconciliation["result"], "discarded")

    def test_race_requires_refusal_for_non_winner(self):
        class RaceErrorClient(_StorageClient):
            def put(self, key, body, **kwargs):
                if key.endswith("race/create") and body == b"create-b":
                    return self._result(500)
                return super().put(key, body, **kwargs)
        status, events = self.run_storage(RaceErrorClient())
        self.assertIs(status, StorageStatus.NO_GO)
        self.assertIn("create race did not produce one winner and one expected refusal", events[-1]["failures"])

    def test_storage_no_go_continues_after_stale_delete_capability_failure(self):
        status, events = self.run_storage(_StorageClient(broken_stale_delete=True))
        self.assertIs(status, StorageStatus.NO_GO)
        operations = [event.get("operation") for event in events]
        self.assertIn("delete-current", operations)
        self.assertIn("discarded-response-reconciliation", operations)
        self.assertIn("stale conditional DELETE was not refused", events[-1]["failures"])
        self.assertEqual(events[-1]["result"], "NO-GO")

    def test_storage_converts_request_exception_to_bounded_no_go_evidence(self):
        class FailingClient(_StorageClient):
            def get(self, key):
                raise TimeoutError("provider timeout")
        status, events = self.run_storage(FailingClient())
        self.assertIs(status, StorageStatus.NO_GO)
        self.assertEqual(events[-2]["operation"], "storage-error")
        self.assertEqual(events[-2]["exception_type"], "TimeoutError")
        self.assertEqual(events[-1]["result"], "NO-GO")

    def test_storage_cli_has_distinct_pass_and_no_go_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            for result, expected in ((StorageStatus.PASS, 0), (StorageStatus.NO_GO, 2)):
                with mock.patch("run.storage", return_value=result), mock.patch("run.write_latest_storage_evidence_pointer"):
                    self.assertEqual(main(["storage", "--work-root", str(Path(directory) / result.name), "--s3-env", "/private/env"]), expected)


class ProvisionTests(unittest.TestCase):
    def _zip(self, path, members):
        with zipfile.ZipFile(path, "w") as archive:
            for name, data, mode in members:
                info = zipfile.ZipInfo(name)
                info.external_attr = mode << 16
                archive.writestr(info, data)

    def _tar(self, path, members):
        with tarfile.open(path, "w:gz") as archive:
            for name, data, mode, kind in members:
                info = tarfile.TarInfo(name)
                info.mode = mode
                info.size = len(data)
                info.type = kind
                archive.addfile(info, io.BytesIO(data))

    def _spec(self, archive_sha, executable_sha, *, kind="zip"):
        return Artifact("demo", "1.2.3", "demo.zip", "https://example.invalid/demo.zip",
                        archive_sha, executable_sha, kind, ("demo", "LICENSE"), "demo")

    def test_architecture_selects_only_exact_linux_assets(self):
        self.assertEqual(artifact_for("trailbase", "x86_64").filename,
                         "trailbase_v0.33.11_x86_64_linux.zip")
        self.assertEqual(artifact_for("litestream", "aarch64").filename,
                         "litestream-0.5.17-linux-arm64.tar.gz")
        for machine in ("amd64", "arm64", "i686", "", "x86_64;touch /tmp/x"):
            with self.assertRaises(ValueError):
                artifact_for("trailbase", machine)
        with self.assertRaises(ValueError):
            artifact_for("unknown", "x86_64")

    def test_release_metadata_and_published_checksum_are_both_exact(self):
        spec = artifact_for("litestream", "x86_64")
        metadata = {"tag_name": "v0.5.17", "draft": False, "prerelease": False, "assets": [
            {"name": spec.filename, "digest": "sha256:" + spec.archive_sha256,
             "browser_download_url": spec.url}
        ]}
        validate_release_metadata(spec, metadata)
        self.assertEqual(published_checksum(f"{spec.archive_sha256}  {spec.filename}\n", spec.filename),
                         spec.archive_sha256)
        for broken in (
            {**metadata, "tag_name": "v0.5.18"},
            {**metadata, "draft": True},
            {**metadata, "assets": [{**metadata["assets"][0], "digest": "sha256:" + "0" * 64}]},
            {**metadata, "assets": [{**metadata["assets"][0], "browser_download_url": "https://example.invalid/x"}]},
        ):
            with self.assertRaises(RuntimeError):
                validate_release_metadata(spec, broken)
        for text in ("", f"{'0' * 64}  {spec.filename}\n",
                     f"{spec.archive_sha256}  ../{spec.filename}\n",
                     f"{spec.archive_sha256}  {spec.filename}\n{spec.archive_sha256}  {spec.filename}\n"):
            with self.assertRaises(RuntimeError):
                published_checksum(text, spec.filename)

    def test_checksum_and_executable_hash_mismatch_refuse_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "demo.zip"
            self._zip(archive, [("demo", b"binary", 0o100755), ("LICENSE", b"license", 0o100644)])
            destination = root / "bin" / "demo"
            bad_archive = self._spec("0" * 64, hashlib.sha256(b"binary").hexdigest())
            with self.assertRaises(RuntimeError):
                extract_verified_artifact(archive, bad_archive, destination)
            self.assertFalse(destination.exists())
            good_archive = hashlib.sha256(archive.read_bytes()).hexdigest()
            bad_binary = self._spec(good_archive, "0" * 64)
            with self.assertRaises(RuntimeError):
                extract_verified_artifact(archive, bad_binary, destination)
            self.assertFalse(destination.exists())

    def test_archive_members_must_be_exact_regular_safe_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            destination = root / "bin" / "demo"
            cases = [
                [("../demo", b"binary", 0o100755), ("LICENSE", b"license", 0o100644)],
                [("/demo", b"binary", 0o100755), ("LICENSE", b"license", 0o100644)],
                [("demo", b"binary", 0o120777), ("LICENSE", b"license", 0o100644)],
                [("demo", b"binary", 0o100755), ("LICENSE", b"license", 0o100644), ("extra", b"x", 0o100644)],
            ]
            for index, members in enumerate(cases):
                archive = root / f"bad-{index}.zip"
                self._zip(archive, members)
                spec = self._spec(hashlib.sha256(archive.read_bytes()).hexdigest(), hashlib.sha256(b"binary").hexdigest())
                with self.assertRaises(RuntimeError):
                    extract_verified_artifact(archive, spec, destination)
                self.assertFalse(destination.exists())

    def test_safe_tar_extracts_only_pinned_executable(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "demo.tar.gz"
            members = [("demo", b"binary", 0o755, tarfile.REGTYPE),
                       ("LICENSE", b"license", 0o644, tarfile.REGTYPE)]
            self._tar(archive, members)
            spec = Artifact("demo", "1.2.3", "demo.tar.gz", "https://example.invalid/demo.tar.gz",
                            hashlib.sha256(archive.read_bytes()).hexdigest(), hashlib.sha256(b"binary").hexdigest(),
                            "tar.gz", ("demo", "LICENSE"), "demo")
            destination = root / "bin" / "demo"
            extract_verified_artifact(archive, spec, destination)
            self.assertEqual(destination.read_bytes(), b"binary")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
            link_archive = root / "link.tar.gz"
            self._tar(link_archive, [("demo", b"", 0o755, tarfile.SYMTYPE),
                                     ("LICENSE", b"license", 0o644, tarfile.REGTYPE)])
            link_spec = Artifact(**{**spec.__dict__, "archive_sha256": hashlib.sha256(link_archive.read_bytes()).hexdigest()})
            with self.assertRaises(RuntimeError):
                extract_verified_artifact(link_archive, link_spec, root / "bin" / "other")

    def test_package_selection_is_idempotent_and_allowlisted(self):
        installed = {"ca-certificates", "curl", "python3"}
        self.assertEqual(missing_packages(installed), ["sqlite3", "unzip"])
        self.assertEqual(missing_packages(installed | {"sqlite3", "unzip"}), [])
        with self.assertRaises(ValueError):
            missing_packages(installed | {"unexpected"})

    def test_installed_package_query_uses_dpkg_status_field_without_shell_expansion(self):
        installed = subprocess.CompletedProcess([], 0, "install ok installed", "")
        with mock.patch("run.subprocess.run", return_value=installed) as execute:
            self.assertEqual(_install_required_packages(), ["ca-certificates", "curl", "python3", "sqlite3", "unzip"])
        self.assertEqual(execute.call_count, 5)
        self.assertTrue(all(call.args[0][2] == "-f=${Status}" for call in execute.call_args_list))

    def test_newly_installed_packages_are_requeried_and_reported_completely(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[0] == "dpkg-query":
                package = argv[-1]
                queried = len([call for call in calls if call[0] == "dpkg-query"])
                installed = queried > 5 or package in {"ca-certificates", "curl", "python3"}
                return subprocess.CompletedProcess(argv, 0 if installed else 1,
                                                   "install ok installed" if installed else "", "")
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch("run.subprocess.run", side_effect=run):
            self.assertEqual(_install_required_packages(), ["ca-certificates", "curl", "python3", "sqlite3", "unzip"])
        self.assertEqual([call[0] for call in calls].count("apt-get"), 2)

    def test_versions_are_exact(self):
        trail = "trail v0.33.11-0-gf24291b8 (2026-09-04)\nsqlite: 3.53.2\n"
        self.assertEqual(validate_binary_version("trailbase", trail), "0.33.11")
        self.assertEqual(validate_binary_version("litestream", "0.5.17\n"), "0.5.17")
        for product, value in (("trailbase", trail.replace("0.33.11", "0.33.110")),
                               ("litestream", "0.5.18\n"),
                               ("litestream", "prefix 0.5.17 suffix\n")):
            with self.assertRaises(RuntimeError):
                validate_binary_version(product, value)

    def test_binary_version_evidence_retains_exact_build_and_embedded_sqlite(self):
        trail = "trail v0.33.11-0-gf24291b8 (2026-09-04)\nsqlite: 3.53.2\n"
        versions, reports = _binary_version_evidence(trail, "0.5.17\n")
        self.assertEqual(versions, {"trailbase": "0.33.11", "litestream": "0.5.17"})
        self.assertEqual(reports["trailbase"], {
            "reported": trail.rstrip(), "build": "v0.33.11-0-gf24291b8",
            "embedded_sqlite_version": "3.53.2",
        })
        self.assertEqual(reports["litestream"], {"reported": "0.5.17"})

    def test_m0_acceptance_requires_exact_matrix_platform_hashes_and_manifest(self):
        machine = "x86_64"
        trail = artifact_for("trailbase", machine).executable_sha256
        litestream = artifact_for("litestream", machine).executable_sha256
        results = [{"scenario": scenario, "iteration": iteration, "status": "PASS",
                    "evidence": {"logs_ref": f"logs/{scenario}-{iteration}/"}}
                   for iteration in range(1, 4)
                   for scenario in ("follow", "graceful", "crash", "lagged-crash")]
        results.append({"scenario": "guards", "iteration": 1, "status": "PASS",
                        "evidence": {"logs_ref": "logs/guards-1/"}})
        aggregate = {"scenario": "all", "status": "PASS", "repeat": 3,
                     "platform": {"system": "Linux", "machine": machine},
                     "trail_sha256": trail, "litestream_sha256": litestream, "results": results}
        result_digest = hashlib.sha256(json.dumps(aggregate).encode()).hexdigest()
        manifest = {"run_count": 1, "result_present": True, "result_sha256": result_digest,
                    "result_status": "PASS", "repeat": 3, "result_count": 13, "log_count": 13,
                    "logs": [{"path": f"logs/{item['scenario']}-{item['iteration']}/log.txt", "sha256": "0" * 64} for item in results]}
        self.assertFalse(_validate_m0_aggregate(node("fm1"), machine, aggregate, manifest, result_digest))

        mutations = []
        for field, value in (("scenario", "follow"), ("status", "FAIL"), ("repeat", 2),
                             ("trail_sha256", "0" * 64), ("litestream_sha256", "0" * 64)):
            mutations.append(({**aggregate, field: value}, manifest, result_digest))
        mutations.extend([
            ({**aggregate, "results": [{**results[0], "evidence": {}}] + results[1:]}, manifest, result_digest),
            ({**aggregate, "results": [{**results[0], "evidence": {"logs_ref": "logs/other/"}}] + results[1:]}, manifest, result_digest),
            ({**aggregate, "platform": {"system": "Darwin", "machine": machine}}, manifest, result_digest),
            ({**aggregate, "platform": {"system": "Linux", "machine": "aarch64"}}, manifest, result_digest),
            ({**aggregate, "results": results[:-1] + [{**results[-1], "scenario": "follow"}]}, manifest, result_digest),
            ({**aggregate, "results": [{**results[0], "untrusted": True}, *results[1:]]}, manifest, result_digest),
            ({**aggregate, "results": [{**results[0], "status": "FAIL"}, *results[1:]]}, manifest, result_digest),
        ])
        for field, value in (("run_count", 2), ("result_present", False), ("result_sha256", "0" * 64),
                             ("result_status", "FAIL"), ("repeat", 2), ("result_count", 12), ("log_count", 0)):
            mutations.append((aggregate, {**manifest, field: value}, result_digest))
        for changed_aggregate, changed_manifest, changed_digest in mutations:
            with self.subTest(aggregate=changed_aggregate, manifest=changed_manifest):
                self.assertFalse(_validate_m0_aggregate(node("fm1"), machine, changed_aggregate,
                                                        changed_manifest, changed_digest))
        self.assertFalse(_validate_m0_aggregate(node("fm2"), machine, aggregate, manifest, result_digest))
        self.assertFalse(_validate_m0_aggregate(node("fm1"), "aarch64", aggregate, manifest, result_digest))

    def test_m0_failure_and_timeout_collect_partial_evidence_and_return_no_go(self):
        for termination in (subprocess.CompletedProcess([], 2, b"", b"private: No space left on device"),
                            subprocess.TimeoutExpired([], 1200, output=b"", stderr=b"private timeout")):
            with self.subTest(termination=type(termination).__name__), tempfile.TemporaryDirectory() as d:
                local = Path(d)
                context = RunContext("20260907T010203Z-0123456789", local,
                                     "/var/lib/hat-qualification/20260907T010203Z-0123456789")
                partial = json.dumps({"run_count": 1, "result_present": False, "log_count": 4}).encode()

                def copy(_node, source, destination, **_kwargs):
                    destination.write_bytes(partial if source.endswith("m0-evidence.json") else b"partial logs")
                    destination.chmod(0o600)

                command = mock.Mock(side_effect=[
                    termination,
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 0, b"", b""),
                ])
                with mock.patch("run._copy_m0_source", return_value=context.remote_root + "/source/experiments/m0"), \
                     mock.patch("run._create_runtime_root", return_value="/run/hat/work"), \
                     mock.patch("run.ssh", command), mock.patch("run._copy_from_node", side_effect=copy), \
                     mock.patch("run._LOADED_SECRET_VALUES", set()):
                    status = _run_m0_linux_parity(node("fm1"), context, local / "evidence.jsonl", local, Path.cwd(), "x86_64")

                self.assertIs(status, StorageStatus.NO_GO)
                self.assertEqual(command.call_args_list[0].args[1][0], "systemd-run")
                self.assertEqual(command.call_args_list[0].args[1][-4:], ["--scenario", "all", "--repeat", "3"])
                self.assertEqual(command.call_args_list[1].args[1][:2], ["systemctl", "stop"])
                self.assertEqual(command.call_args_list[2].args[1][:2], ["systemctl", "reset-failed"])
                self.assertIn("m0-evidence.json", command.call_args_list[3].args[1][2])
                event = json.loads((local / "evidence.jsonl").read_text().splitlines()[-1])
                self.assertEqual((event["event"], event["status"], event["repeat"]),
                                 ("m0-linux-parity", "NO-GO", 3))
                self.assertNotIn("private", json.dumps(event))
                if isinstance(termination, subprocess.CompletedProcess):
                    self.assertEqual(event["failures"], ["resource capability: no space left on device", "copied logs are unsafe or incomplete"])
                self.assertTrue((local / "fm1-m0-evidence.json").is_file())
                self.assertTrue((local / "fm1-m0-logs.tar.gz").is_file())

    def test_copy_from_node_hard_bounds_and_atomically_publishes(self):
        realpath = subprocess.CompletedProcess([], 0, b"/safe/file\n", b"")
        for payload, succeeds in ((b"1234", True), (b"12345", False)):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as d:
                destination = Path(d) / "copy"
                copied = subprocess.CompletedProcess([], 0, payload, b"")
                transport = mock.Mock(side_effect=[realpath, copied])
                with mock.patch("run._REMOTE_ROOT", "/safe"), \
                     mock.patch("run._SSH_KNOWN_HOSTS", Path("/pins")), \
                     mock.patch("run._remote_stat", return_value=("regular file", 0, 0, 0o600, "/safe/file")), \
                     mock.patch("run.ssh", transport):
                    if succeeds:
                        _copy_from_node(node(), "/safe/file", destination, max_bytes=4)
                    else:
                        with self.assertRaises(RuntimeError):
                            _copy_from_node(node(), "/safe/file", destination, max_bytes=4)
                self.assertEqual(destination.exists(), succeeds)
                if succeeds:
                    self.assertEqual(destination.read_bytes(), payload)
                    self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                bounded_command = transport.call_args_list[1].args[1]
                self.assertEqual(bounded_command[:2], ["python3", "-c"])
                self.assertEqual(bounded_command[-2:], ["/safe/file", "5"])

    def test_provision_uses_long_timeout_and_records_sanitized_no_go(self):
        timeout = subprocess.TimeoutExpired([], REMOTE_PROVISION_TIMEOUT, stderr=b"private detail")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); evidence = root / "evidence.jsonl"
            context = RunContext("20260907T010203Z-0123456789", root,
                                 "/var/lib/hat-qualification/20260907T010203Z-0123456789")
            with mock.patch("run._validate_prerequisites"), mock.patch("run._validate_local_context", return_value=root), \
                 mock.patch("run._validate_evidence_path", return_value=evidence), \
                 mock.patch("run.build_pinned_known_hosts", return_value=root / "pins"), \
                 mock.patch("run._verify_remote_directory"), mock.patch("run.scp_to"), \
                 mock.patch("run.ssh", side_effect=timeout) as transport, \
                 mock.patch("run._LOADED_SECRET_VALUES", set()):
                status = provision([node("fm1")], context, evidence, Path.cwd(),
                                   inventory_path=root / "inventory", linode_env=root / "env", fence_command=root / "fence")
            self.assertIs(status, StorageStatus.NO_GO)
            self.assertEqual(transport.call_args.kwargs["timeout"], REMOTE_PROVISION_TIMEOUT)
            event = json.loads(evidence.read_text().splitlines()[-1])
            self.assertEqual(event, {"event": "provision", "status": "NO-GO",
                                     "stage": "provision:fm1", "exception_type": "TimeoutExpired"})
            self.assertNotIn("private", json.dumps(event))

    def test_provision_cli_bounds_preflight_failure_and_records_no_go(self):
        nodes = [node("fm1"), node("fm2"), node("fm3")]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "runs"; local = root / "20260907T010203Z-0123456789"; local.mkdir(mode=0o700, parents=True)
            context = RunContext(local.name, local, "/var/lib/hat-qualification/" + local.name)
            with mock.patch("run.load_inventory", return_value=nodes), mock.patch("run.load_linode_env"), \
                 mock.patch("run.new_run_context", return_value=context), \
                 mock.patch("run.preflight", side_effect=RuntimeError("private preflight detail")), \
                 mock.patch("run.init_remote"):
                status = main(["provision", "--inventory", str(Path(d) / "inventory"),
                               "--linode-env", str(Path(d) / "env"), "--fence-command", str(Path(d) / "fence"),
                               "--work-root", str(root)])
            self.assertEqual(status, 2)
            event = json.loads((local / "evidence.jsonl").read_text().splitlines()[-1])
            self.assertEqual(event["status"], "NO-GO")
            self.assertEqual(event["stage"], "preflight/init")
            self.assertNotIn("private", json.dumps(event))

    def test_provision_boundary_keeps_no_go_when_evidence_write_fails(self):
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("run._provision_workflow", side_effect=RuntimeError("private detail")), \
                 mock.patch("run.append_evidence", side_effect=OSError("disk full")):
                self.assertIs(provision([], RunContext("20260907T010203Z-0123456789", Path(d), "/safe"),
                                      Path(d) / "evidence.jsonl", Path.cwd(), inventory_path=Path(d) / "i",
                                      linode_env=Path(d) / "e", fence_command=Path(d) / "f"), StorageStatus.NO_GO)

    def test_provision_cli_returns_two_for_bounded_m0_no_go(self):
        nodes = [node("fm1"), node("fm2"), node("fm3")]
        with tempfile.TemporaryDirectory() as d, \
             mock.patch("run.load_inventory", return_value=nodes), mock.patch("run.load_linode_env"), \
             mock.patch("run.preflight"), mock.patch("run.init_remote"), \
             mock.patch("run.provision", return_value=StorageStatus.NO_GO):
            root = Path(d) / "runs"
            self.assertEqual(main(["provision", "--inventory", str(Path(d) / "inventory"),
                                   "--linode-env", str(Path(d) / "env"), "--fence-command", str(Path(d) / "fence"),
                                   "--work-root", str(root)]), 2)

    def test_remote_paths_are_confined_and_normalized(self):
        root = "/var/lib/hat-qualification/20260907T010203Z-0123456789"
        self.assertEqual(confined_remote_path(root, root + "/bin/trail"), root + "/bin/trail")
        for candidate in (root, root + "/../escape", root + "//bin", "/tmp/trail", root + "/bin/./trail"):
            with self.assertRaises(ValueError):
                confined_remote_path(root, candidate)

    def test_writer_service_masks_are_persistent_and_fail_closed(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[1:2] == ["is-enabled"]:
                return subprocess.CompletedProcess(argv, 0, stdout="masked\n", stderr="")
            if argv[1:2] == ["is-active"]:
                return subprocess.CompletedProcess(argv, 3, stdout="inactive\n", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d:
            service_dir = Path(d)
            mask_writer_services(service_dir, run=run)
            for unit in ("hat-trailbase.service", "hat-litestream.service"):
                self.assertTrue((service_dir / unit).is_symlink())
                self.assertEqual(os.readlink(service_dir / unit), "/dev/null")
            mask_writer_services(service_dir, run=run)
            self.assertIn(["systemctl", "daemon-reload"], calls)
            (service_dir / "hat-trailbase.service").unlink()
            (service_dir / "hat-trailbase.service").write_text("[Service]\nExecStart=/bin/true\n")
            with self.assertRaises(RuntimeError):
                mask_writer_services(service_dir, run=run)

    def test_writer_service_query_error_is_not_treated_as_inactive(self):
        with tempfile.TemporaryDirectory() as d:
            def broken(argv, **kwargs):
                if argv[1:2] == ["is-enabled"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="masked\n", stderr="")
                if argv[1:2] == ["is-active"]:
                    return subprocess.CompletedProcess(argv, 1, stdout="", stderr="query failed")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            with self.assertRaises(RuntimeError):
                mask_writer_services(Path(d), run=broken)

    def test_writer_containment_attempts_sibling_after_first_stop_failure(self):
        calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if argv[1:3] == ["stop", "hat-trailbase.service"]:
                return subprocess.CompletedProcess(argv, 1, stdout="", stderr="failed")
            if argv[1:2] == ["is-active"]:
                return subprocess.CompletedProcess(argv, 3, stdout="inactive\n", stderr="")
            if argv[1:2] == ["is-enabled"]:
                return subprocess.CompletedProcess(argv, 0, stdout="masked\n", stderr="")
            return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(RuntimeError):
                mask_writer_services(Path(d), run=run)
        self.assertIn(["systemctl", "stop", "hat-litestream.service"], calls)
        self.assertIn(["systemctl", "is-active", "hat-litestream.service"], calls)
        self.assertIn(["systemctl", "daemon-reload"], calls)

    def test_provision_summary_and_reboot_parity_are_exact(self):
        machine = "x86_64"
        trail = "trail v0.33.11-0-gf24291b8 (2026-09-04)\nsqlite: 3.53.2"
        summary = {"status": "PASS", "architecture": machine, "installed_packages": ["ca-certificates", "curl", "python3", "sqlite3", "unzip"],
                   "versions": {"trailbase": "0.33.11", "litestream": "0.5.17"},
                   "binary_versions": {"trailbase": {"reported": trail, "build": "v0.33.11-0-gf24291b8",
                                                        "embedded_sqlite_version": "3.53.2"},
                                       "litestream": {"reported": "0.5.17"}},
                   "archives": {p: artifact_for(p, machine).archive_sha256 for p in ("trailbase", "litestream")},
                   "executables": {p: artifact_for(p, machine).executable_sha256 for p in ("trailbase", "litestream")},
                   "services": {"hat-trailbase.service": "masked-and-inactive",
                                "hat-litestream.service": "masked-and-inactive"}}
        _validate_provision_summary(summary)
        for packages in (summary["installed_packages"][:-1], [*summary["installed_packages"], "unexpected"]):
            with self.assertRaises(RuntimeError):
                _validate_provision_summary({**summary, "installed_packages": packages})
        post = dict(summary)
        _validate_post_reboot_summary(post, summary)
        for packages in (summary["installed_packages"][:-1], [*summary["installed_packages"], "unexpected"]):
            with self.assertRaises(RuntimeError):
                _validate_post_reboot_summary({**post, "installed_packages": packages}, summary)
        for field in ("archives", "executables", "versions", "binary_versions", "services"):
            changed = dict(post)
            changed[field] = dict(post[field])
            changed[field][next(iter(changed[field]))] = "mutated"
            with self.assertRaises(RuntimeError):
                _validate_post_reboot_summary(changed, summary)

    def test_three_node_provision_fixture_records_reboot_parity_and_mutation_no_go(self):
        machine = "x86_64"
        trail = "trail v0.33.11-0-gf24291b8 (2026-09-04)\nsqlite: 3.53.2"
        summary = {"status": "PASS", "architecture": machine, "installed_packages": ["ca-certificates", "curl", "python3", "sqlite3", "unzip"],
                   "versions": {"trailbase": "0.33.11", "litestream": "0.5.17"},
                   "binary_versions": {"trailbase": {"reported": trail, "build": "v0.33.11-0-gf24291b8",
                                                        "embedded_sqlite_version": "3.53.2"},
                                       "litestream": {"reported": "0.5.17"}},
                   "archives": {p: artifact_for(p, machine).archive_sha256 for p in ("trailbase", "litestream")},
                   "executables": {p: artifact_for(p, machine).executable_sha256 for p in ("trailbase", "litestream")},
                   "services": {"hat-trailbase.service": "masked-and-inactive",
                                "hat-litestream.service": "masked-and-inactive"}}
        nodes = [node(name) for name in ("fm1", "fm2", "fm3")]
        context = RunContext("20260907T010203Z-0123456789", Path("."),
                             "/var/lib/hat-qualification/20260907T010203Z-0123456789")
        for mutate in (False, True):
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as d:
                root = Path(d); evidence = root / "evidence.jsonl"
                post = dict(summary)
                if mutate:
                    post["executables"] = dict(post["executables"])
                    post["executables"]["trailbase"] = "0" * 64
                def ssh_fixture(current, argv, **kwargs):
                    if "__remote-provision" in argv:
                        return subprocess.CompletedProcess([], 0, json.dumps(summary), "")
                    if "__remote-verify" in argv:
                        return subprocess.CompletedProcess([], 0, json.dumps(post), "")
                    raise AssertionError(argv)
                with mock.patch("run._validate_prerequisites"), mock.patch("run._validate_local_context", return_value=root), \
                     mock.patch("run._validate_evidence_path", return_value=evidence), mock.patch("run.build_pinned_known_hosts", return_value=root / "pins"), \
                     mock.patch("run._verify_remote_directory"), mock.patch("run.scp_to"), mock.patch("run.ssh", side_effect=ssh_fixture), \
                     mock.patch("run.invoke_fence", return_value={"valid": True, "evidence": {"state": "running"}}), \
                     mock.patch("run._preflight_boot_ids", return_value={n.name: "01234567-89ab-cdef-0123-456789abcdef" for n in nodes}), \
                     mock.patch("run._require_live_identity"), mock.patch("run._verify_reboot", return_value="01234567-89ab-cdef-0123-456789abcdef"), \
                     mock.patch("run._run_m0_linux_parity", return_value=StorageStatus.PASS):
                    result = _provision_workflow(nodes, context, evidence, Path.cwd(),
                                                 inventory_path=root / "inventory", linode_env=root / "env",
                                                 fence_command=root / "fence")
                self.assertIs(result, StorageStatus.NO_GO if mutate else StorageStatus.PASS)
                events = [json.loads(line) for line in evidence.read_text().splitlines()]
                self.assertEqual(sum(event.get("event") == "provision" and "node" in event for event in events), 3)
                if not mutate:
                    self.assertEqual(sum(event.get("event") == "reboot-mask-check" for event in events), 3)

    def test_download_rejects_http_and_credentialed_redirects(self):
        for final_url in ("http://github.com/release", "https://user@github.com/release"):
            with self.subTest(final_url=final_url), tempfile.TemporaryDirectory() as d:
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.geturl.return_value = final_url
                response.read.side_effect = [b"payload", b""]
                with mock.patch("run.urllib.request.urlopen", return_value=response):
                    with self.assertRaises(RuntimeError):
                        _download_public("https://github.com/start", Path(d) / "artifact", max_bytes=1024)
                self.assertFalse((Path(d) / "artifact").exists())

    def test_archive_member_rejects_any_backslash_or_non_logs_path(self):
        for name in ("logs\\evil.log", "logs\\\\evil.log", "logs/../evil.log", "README.md", "evil.log", "logs/"):
            self.assertFalse(_safe_archive_member(name))
        self.assertTrue(_safe_archive_member("logs/worker.log"))

    def test_m0_collector_writes_archive_for_real_logs(self):
        with tempfile.TemporaryDirectory() as d:
            root, output = Path(d) / "root", Path(d) / "out"
            logs = root / "run-1" / "follow-1" / "logs"
            logs.mkdir(parents=True); output.mkdir()
            (logs / "worker.log").write_text("ok\\n")
            result = subprocess.run(["python3", "-c", _M0_COLLECT_SCRIPT, str(root), str(output)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            evidence = json.loads((output / "m0-evidence.json").read_text())
            self.assertEqual(evidence["logs"][0]["path"], "logs/follow-1/logs/worker.log")
            with tarfile.open(output / "m0-logs.tar.gz", "r:gz") as archive:
                self.assertEqual(archive.getnames(), ["logs/follow-1/logs/worker.log"])

    def test_m0_collector_rejects_symlinked_run_root(self):
        with tempfile.TemporaryDirectory() as d:
            root, output = Path(d) / "root", Path(d) / "out"
            root.mkdir(mode=0o700); output.mkdir(mode=0o700)
            target = root / "real"; target.mkdir()
            (root / "run-1").symlink_to(target, target_is_directory=True)
            result = subprocess.run(["python3", "-c", _M0_COLLECT_SCRIPT, str(root), str(output)],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_m0_log_archive_requires_exact_safe_manifest_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); archive_path = root / "logs.tar.gz"
            data = b"partial log\\n"
            with tarfile.open(archive_path, "w:gz") as archive:
                info = tarfile.TarInfo("logs/worker.log"); info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            manifest = {"log_count": 1, "logs": [{"path": "logs/worker.log",
                                                   "sha256": hashlib.sha256(data).hexdigest()}]}
            self.assertTrue(_validate_m0_log_archive(archive_path, manifest))
            for mutation in ({**manifest, "logs": [{"path": "../escape", "sha256": manifest["logs"][0]["sha256"]}]},
                             {**manifest, "logs": [{"path": "README.md", "sha256": manifest["logs"][0]["sha256"]}]},
                             {**manifest, "logs": [*manifest["logs"], manifest["logs"][0]]},
                             {**manifest, "logs": [{"path": "logs/worker.log", "sha256": "0" * 64}]}):
                self.assertFalse(_validate_m0_log_archive(archive_path, mutation))

    def test_m0_archive_rejects_non_logs_tar_member_and_duplicate_members(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); data = b"partial log\\n"
            manifest = {"log_count": 1, "logs": [{"path": "logs/worker.log", "sha256": hashlib.sha256(data).hexdigest()}]}
            for member_names in (("logs/worker.log", "README.md"), ("logs/worker.log", "logs/worker.log")):
                archive_path = root / ("-".join(member_names).replace("/", "_") + ".tar.gz")
                with tarfile.open(archive_path, "w:gz") as archive:
                    for name in member_names:
                        info = tarfile.TarInfo(name); info.size = len(data)
                        archive.addfile(info, io.BytesIO(data))
                self.assertFalse(_validate_m0_log_archive(archive_path, manifest))


if __name__ == "__main__": unittest.main()
