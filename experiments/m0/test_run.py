import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from run import (
    OwnedProcess,
    require_private_run_root,
    require_stopped,
    stop_owned,
    validate_inventory,
    validate_binary_versions,
    write_fixture,
    normalize_txid,
    read_txid_sidecar,
    require_files,
    parse_follower_line,
    promotion_error_gate,
    wait_ready,
    FIXTURE_USERNAME,
    parse_binary_versions,
    format_txid,
    promote_candidate,
    validate_epoch_paths,
    copy_for_inspection,
    sqlite_rows,
    outcomes,
    outcome_passes,
)


class RunRootTests(unittest.TestCase):
    def test_rejects_existing_populated_root(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            (root / "existing").write_text("x")
            with self.assertRaises(ValueError):
                require_private_run_root(root, Path(parent) / "repo")

    def test_rejects_existing_empty_root(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "run"
            root.mkdir()
            with self.assertRaises(ValueError):
                require_private_run_root(root, Path(parent) / "repo")

    def test_rejects_symlinked_ancestor_into_repository(self):
        with tempfile.TemporaryDirectory() as parent:
            parent = Path(parent)
            repo = parent / "repo"
            repo.mkdir()
            alias = parent / "alias"
            alias.symlink_to(repo, target_is_directory=True)
            with self.assertRaises(ValueError):
                require_private_run_root(alias / "run", repo)

    def test_rejects_root_inside_repository(self):
        with tempfile.TemporaryDirectory() as parent:
            repo = Path(parent) / "repo"
            repo.mkdir()
            with self.assertRaises(ValueError):
                require_private_run_root(repo / "run", repo)


class ReadinessTests(unittest.TestCase):
    def test_plain_text_health_and_forbidden_api_mean_ready(self):
        child = OwnedProcess(mock.Mock(poll=mock.Mock(return_value=None)), "trail")
        with mock.patch("run.http_request", side_effect=[(200, b"Ok"), (403, b"")]):
            wait_ready("http://127.0.0.1:1", child, timeout=0.1)


class OutcomeTests(unittest.TestCase):
    def test_acknowledged_and_ambiguous_are_distinct(self):
        result = outcomes({"a", "b"}, set(), {"c"}, {"a", "c"}, {"a", "b", "c"})
        self.assertEqual(result["lost_acknowledged"], ["b"])
        self.assertEqual(result["recovered_ambiguous"], ["c"])
        self.assertEqual(result["recovered_rejected"], [])
        self.assertEqual(result["unexpected"], [])

    def test_recovered_rejection_is_not_ambiguous(self):
        result = outcomes(set(), {"denied"}, set(), {"denied"}, {"denied"})
        self.assertEqual(result["recovered_rejected"], ["denied"])
        self.assertEqual(result["recovered_ambiguous"], [])
        self.assertFalse(outcome_passes(result))

    def test_outcome_classes_must_partition_submissions(self):
        with self.assertRaises(ValueError):
            outcomes({"same"}, {"same"}, set(), set(), {"same"})
        with self.assertRaises(ValueError):
            outcomes(set(), set(), set(), set(), {"missing"})

    def test_unexpected_recovered_operation_fails(self):
        result = outcomes(set(), set(), set(), {"unexpected"}, set())
        self.assertFalse(outcome_passes(result))


class PromotionTests(unittest.TestCase):
    def test_inspection_uses_a_copy_of_candidate(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            source = root / "candidate.db"
            source.write_bytes(b"candidate")
            copied = copy_for_inspection(source, root / "evidence")
            copied.write_bytes(b"inspected")
            self.assertEqual(source.read_bytes(), b"candidate")

    def test_truncated_candidate_fails_validation(self):
        with tempfile.TemporaryDirectory() as parent:
            candidate = Path(parent) / "main.db"
            candidate.write_bytes(b"not sqlite")
            with self.assertRaises(Exception):
                sqlite_rows(candidate, ("hat_ops",))

    def test_missing_session_prevents_start(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            for name in ("main", "aux"):
                (root / f"{name}.db").write_bytes(b"db")
            start = mock.Mock()
            with self.assertRaises(FileNotFoundError):
                promote_candidate([], [root / f"{name}.db" for name in ("main", "session", "aux")], start)
            start.assert_not_called()

    def test_live_follower_prevents_start(self):
        live = OwnedProcess(mock.Mock(poll=mock.Mock(return_value=None)), "follower")
        start = mock.Mock()
        with self.assertRaises(RuntimeError):
            promote_candidate([live], [], start)
        start.assert_not_called()

    def test_epoch_rejects_cross_database_destination_alias(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            with self.assertRaises(ValueError):
                validate_epoch_paths(
                    {"main": root / "e1-main", "session": root / "e1-session"},
                    {"main": root / "e2-shared", "session": root / "e2-shared"},
                )

    def test_new_epoch_paths_must_not_reuse_e1(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            with self.assertRaises(ValueError):
                validate_epoch_paths({"main": root / "e1"}, {"main": root / "e1"})


class ProcessOwnershipTests(unittest.TestCase):
    def test_only_owned_processes_are_stopped(self):
        process = subprocess.Popen(
            ["python3", "-c", "import time; time.sleep(30)"],
            start_new_session=True,
        )
        owned = OwnedProcess(process, "test")
        try:
            stop_owned([owned], timeout=2)
            self.assertIsNotNone(process.poll())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_promotion_requires_all_children_stopped(self):
        live = mock.Mock(poll=mock.Mock(return_value=None))
        with self.assertRaises(RuntimeError):
            require_stopped([OwnedProcess(live, "follower")])

    def test_stopped_children_are_accepted(self):
        stopped = mock.Mock(poll=mock.Mock(return_value=0))
        require_stopped([OwnedProcess(stopped, "follower")])


class FixtureTests(unittest.TestCase):
    def test_fixture_username_uses_trailbase_supported_characters(self):
        self.assertEqual(FIXTURE_USERNAME, "m0user")
        self.assertTrue(FIXTURE_USERNAME.isalnum())

    def test_inventory_requires_exact_business_databases(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            paths = {name: root / f"{name}.db" for name in ("main", "session", "aux")}
            self.assertEqual(validate_inventory(paths), paths)
            with self.assertRaises(ValueError):
                validate_inventory({**paths, "logs": root / "logs.db"})

    def test_inventory_rejects_symlink_aliases(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            target = root / "target"
            target.mkdir()
            alias = root / "alias"
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises(ValueError):
                validate_inventory({"main": target / "same.db", "session": alias / "same.db", "aux": root / "aux.db"})

    def test_inventory_rejects_duplicate_resolved_paths(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            with self.assertRaises(ValueError):
                validate_inventory({"main": root / "same.db", "session": root / "same.db", "aux": root / "aux.db"})

    def test_parses_pinned_binary_versions(self):
        self.assertEqual(
            parse_binary_versions("trail v0.33.11-0-gf24291b8 (2026-09-04)\nsqlite: 3.53.2\n", "0.5.17\n"),
            {"trail": "0.33.11", "litestream": "0.5.17"},
        )

    def test_binary_versions_must_match(self):
        with self.assertRaises(ValueError):
            validate_binary_versions({"trail": "0.33.11", "litestream": "0.5.17"}, {"trail": "0.33.10", "litestream": "0.5.17"})

    def test_formats_fixed_width_litestream_txid(self):
        self.assertEqual(format_txid(2), "0000000000000002")

    def test_normalizes_decimal_and_hex_positions(self):
        self.assertEqual(normalize_txid(17), 17)
        self.assertEqual(normalize_txid("0x11"), 17)
        self.assertEqual(normalize_txid("11"), 17)

    def test_rejects_malformed_txid_sidecar(self):
        with tempfile.TemporaryDirectory() as parent:
            sidecar = Path(parent) / "main.db-txid"
            sidecar.write_text("not-a-position")
            with self.assertRaises(ValueError):
                read_txid_sidecar(sidecar)

    def test_required_files_are_checked_before_opening(self):
        with tempfile.TemporaryDirectory() as parent:
            with self.assertRaises(FileNotFoundError):
                require_files([Path(parent) / "main.db"])

    def test_follower_parser_accepts_pinned_info_format(self):
        event = parse_follower_line('time=2026-01-01T00:00:00Z level=INFO msg="follow: applied updates" txid=1')
        self.assertEqual(event["level"], "INFO")
        self.assertFalse(event["error"])

    def test_follower_parser_fails_closed_on_unknown_format(self):
        with self.assertRaises(RuntimeError):
            promotion_error_gate([parse_follower_line("unexpected follower output")])

    def test_follower_parser_recognizes_json_error_severity(self):
        with self.assertRaises(RuntimeError):
            promotion_error_gate([parse_follower_line('{"level":"ERROR","msg":"storage failed"}')])

    def test_follower_error_remains_a_promotion_failure_after_progress(self):
        error = parse_follower_line("level=ERROR msg=\\\"follow: error applying updates\\\"")
        progress = parse_follower_line('{"txid": 42}')
        self.assertTrue(error["error"])
        self.assertEqual(progress["txid"], 42)
        with self.assertRaises(RuntimeError):
            promotion_error_gate([error, progress])

    def test_fixture_uses_username_registration_to_avoid_broken_user_cli(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "traildepot"
            write_fixture(root)
            self.assertIn("auth { user_identifier: ONLY_USERNAME }", (root / "config.textproto").read_text())

    def test_fixture_names_the_application(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "traildepot"
            write_fixture(root)
            self.assertIn('application_name: "HAT M0"', (root / "config.textproto").read_text())

    def test_disabled_jobs_keep_release_default_schedules(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "traildepot"
            write_fixture(root)
            config = (root / "config.textproto").read_text()
            self.assertIn('id: BACKUP schedule: "@daily" disabled: true', config)
            self.assertIn('id: HEARTBEAT schedule: "17 * * * * * *" disabled: true', config)

    def test_fixture_separates_system_jobs_with_commas(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "traildepot"
            write_fixture(root)
            config = (root / "config.textproto").read_text()
            self.assertIn('schedule: "@daily" disabled: true },', config)
            self.assertIn('schedule: "17 * * * * * *" disabled: true },', config)

    def test_fixture_writes_only_configuration_and_migrations(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "a" / "traildepot"
            write_fixture(root)
            self.assertTrue((root / "config.textproto").is_file())
            self.assertTrue((root / "migrations" / "main" / "U100__hat_ops.sql").is_file())
            self.assertTrue((root / "migrations" / "aux" / "U100__hat_ops.sql").is_file())
            self.assertFalse((root / "data" / "main.db").exists())


if __name__ == "__main__":
    unittest.main()
