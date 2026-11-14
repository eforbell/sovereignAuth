"""File trust for the snapshot reader (D18); the port of test/snapshot.test.js. These run as an ordinary
user, so "the Home Base user" is the user running the tests; ownership by another real user is proven on the
test VM."""

from __future__ import annotations

import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sovereign_auth import SnapshotError, SnapshotReader, read_owned_file
from sovereign_auth.snapshot import parse_timestamp_ms

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
BASE = json.loads((VECTORS / "snapshot.json").read_text("utf-8"))["snapshot"]
UID = os.getuid()
T0 = parse_timestamp_ms("2026-10-28T19:00:00.000Z")


def iso(ms: int) -> str:
    import datetime

    moment = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def snapshot_at(ms: int, generation: int = 7) -> dict:
    data = copy.deepcopy(BASE)
    data["generation"] = generation
    data["written_at"] = iso(ms)
    return data


def write_snapshot(data, file: str) -> None:
    """Home Base's writer, reduced to what the tests need: a whole new file renamed into place, 0644."""
    temp = f"{file}.tmp"
    with open(temp, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.chmod(temp, 0o644)
    os.replace(temp, file)


class Tree:
    """A tree like /var/lib/sovereign-home/identity/snapshot.json under a fresh directory that stands in for
    the root-owned part of the path."""

    def __init__(self, test: unittest.TestCase):
        self.root = os.path.realpath(tempfile.mkdtemp(prefix="sovereign-snapshot-"))
        test.addCleanup(shutil.rmtree, self.root, True)
        self.dir = os.path.join(self.root, "identity")
        os.mkdir(self.dir)
        os.chmod(self.dir, 0o755)
        self.file = os.path.join(self.dir, "snapshot.json")
        self.clock = T0

    def reader(self, **options) -> SnapshotReader:
        settings = {"home_base_uid": UID, "file": self.file, "trusted_root": self.root, "now": lambda: self.clock}
        settings.update(options)
        return SnapshotReader(**settings)

    def write(self, data) -> None:
        write_snapshot(data, self.file)


class SnapshotReaderTests(unittest.TestCase):
    def test_a_snapshot_written_by_the_home_base_user_is_read(self):
        tree = Tree(self)
        tree.write(snapshot_at(T0))
        state = tree.reader().current()
        self.assertTrue(state.ok, state.message)
        self.assertEqual(state.snapshot.household, "smith")
        self.assertEqual(state.snapshot.by_user_id["1001"].member_id, "m_parent")
        self.assertIn("k1", state.snapshot.keys)

    def test_missing_symlinked_linked_writable_or_foreign_snapshots_are_refused(self):
        def symlinked(tree):
            write_snapshot(snapshot_at(T0), os.path.join(tree.dir, "real.json"))
            os.symlink(os.path.join(tree.dir, "real.json"), tree.file)

        def group_writable(tree):
            tree.write(snapshot_at(T0))
            os.chmod(tree.file, 0o664)

        def other_writable(tree):
            tree.write(snapshot_at(T0))
            os.chmod(tree.file, 0o646)

        def second_link(tree):
            tree.write(snapshot_at(T0))
            os.link(tree.file, os.path.join(tree.root, "elsewhere.json"))

        def directory_writable(tree):
            tree.write(snapshot_at(T0))
            os.chmod(tree.dir, 0o757)

        def not_json(tree):
            Path(tree.file).write_text('{"format":', "utf-8")
            os.chmod(tree.file, 0o644)

        def nan(tree):
            Path(tree.file).write_text(json.dumps(snapshot_at(T0)).replace('"global_epoch": 2', '"global_epoch": NaN'), "utf-8")
            os.chmod(tree.file, 0o644)

        def other_format(tree):
            data = snapshot_at(T0)
            data["format"] = 2
            tree.write(data)

        def too_big(tree):
            data = snapshot_at(T0)
            data["padding"] = "x" * (1024 * 1024)
            tree.write(data)

        cases = [
            ("missing", lambda tree: None, "missing"),
            ("the file is a symlink", symlinked, "untrusted"),
            ("the file is writable by its group", group_writable, "untrusted"),
            ("the file is writable by others", other_writable, "untrusted"),
            ("the file has a second link", second_link, "untrusted"),
            ("the file is a directory", lambda tree: os.mkdir(tree.file), "untrusted"),
            ("the directory is writable by others", directory_writable, "untrusted"),
            ("the file is not JSON", not_json, "malformed"),
            ("NaN is not JSON", nan, "malformed"),
            ("the file is another format", other_format, "format"),
            ("the file is larger than 1 MiB", too_big, "malformed"),
        ]
        for name, arrange, reason in cases:
            with self.subTest(name):
                tree = Tree(self)
                arrange(tree)
                state = tree.reader().current()
                self.assertFalse(state.ok)
                self.assertEqual(state.reason, reason, state.message)

    def test_a_fifo_in_place_of_the_snapshot_is_refused_without_blocking(self):
        tree = Tree(self)
        os.mkfifo(tree.file)
        self.assertEqual(tree.reader().current().reason, "untrusted")

    def test_the_directory_must_be_the_home_base_users_and_everything_above_it_roots(self):
        tree = Tree(self)
        tree.write(snapshot_at(T0))
        self.assertEqual(tree.reader(home_base_uid=UID + 1).current().reason, "untrusted")

        nested = os.path.join(tree.root, "lib", "identity")
        os.makedirs(nested)
        os.chmod(os.path.join(tree.root, "lib"), 0o755)
        os.chmod(nested, 0o755)
        nested_file = os.path.join(nested, "snapshot.json")
        write_snapshot(snapshot_at(T0), nested_file)
        state = SnapshotReader(home_base_uid=UID, file=nested_file, trusted_root=tree.root, now=lambda: T0).current()
        self.assertEqual(state.reason, "untrusted")
        self.assertRegex(state.message, r"lib is owned by uid")

        os.symlink(tree.dir, os.path.join(tree.root, "link"))
        linked = SnapshotReader(home_base_uid=UID, file=os.path.join(tree.root, "link", "snapshot.json"), trusted_root=tree.root, now=lambda: T0)
        self.assertEqual(linked.current().reason, "untrusted")

    def test_read_owned_file_applies_the_same_ownership_rules_to_any_file(self):
        tree = Tree(self)
        file = os.path.join(tree.dir, "members.json")
        Path(file).write_text('{"members":[]}', "utf-8")
        os.chmod(file, 0o644)
        self.assertEqual(read_owned_file(file, uid=UID, trusted_root=tree.root), '{"members":[]}')

        def refused(target, **options):
            settings = {"uid": UID, "trusted_root": tree.root}
            settings.update(options)
            try:
                read_owned_file(target, **settings)
            except SnapshotError as error:
                return error.reason
            return "read"

        self.assertEqual(refused(file, uid=UID + 1), "untrusted")
        os.symlink(file, os.path.join(tree.dir, "link.json"))
        self.assertEqual(refused(os.path.join(tree.dir, "link.json")), "untrusted")
        os.chmod(file, 0o666)
        self.assertEqual(refused(file), "untrusted")
        os.chmod(file, 0o644)
        os.chmod(tree.dir, 0o777)
        self.assertEqual(refused(file), "untrusted")
        os.chmod(tree.dir, 0o755)
        self.assertEqual(refused(os.path.join(tree.dir, "absent.json")), "missing")
        with self.assertRaisesRegex(ValueError, "owner's uid"):
            read_owned_file(file, uid=True, trusted_root=tree.root)

    def test_freshness_is_checked_on_every_call(self):
        tree = Tree(self)
        tree.write(snapshot_at(T0))
        reader = tree.reader()
        tree.clock = T0 + 120_000
        self.assertTrue(reader.current().ok, "exactly 120 s old is still fresh")
        tree.clock = T0 + 120_001
        self.assertEqual(reader.current().reason, "stale")
        tree.clock = T0 - 31_000
        self.assertEqual(reader.current().reason, "future")

    def test_the_file_is_reread_at_most_every_5_s_and_a_refusal_is_not_remembered_as_good(self):
        tree = Tree(self)
        tree.write(snapshot_at(T0, 7))
        reader = tree.reader()
        self.assertEqual(reader.current().snapshot.generation, 7)
        tree.write(snapshot_at(T0, 8))
        tree.clock = T0 + 4_999
        self.assertEqual(reader.current().snapshot.generation, 7, "not re-read yet")
        tree.clock = T0 + 5_000
        self.assertEqual(reader.current().snapshot.generation, 8)
        os.chmod(tree.file, 0o666)
        tree.clock = T0 + 10_000
        self.assertEqual(reader.current().reason, "untrusted")
        tree.clock = T0 + 12_000
        self.assertEqual(reader.current().reason, "untrusted", "still refused until the next re-read")
        os.chmod(tree.file, 0o644)
        tree.clock = T0 + 15_000
        self.assertEqual(reader.current().snapshot.generation, 8)

    def test_a_reload_that_fails_in_any_way_never_leaves_the_old_snapshot_in_force(self):
        """A reload that raises something other than SnapshotError (Python's recursion limit on deep JSON, a
        year the calendar can't hold) must replace the snapshot it held, for this request and the next."""
        disabled = copy.deepcopy(BASE["members"])
        disabled[0]["status"] = "disabled"
        for name, extra, written_at in [
            ("deep nesting", None, None),
            ("year zero", None, "0000-01-01T00:00:00Z"),
        ]:
            with self.subTest(name):
                tree = Tree(self)
                tree.write(snapshot_at(T0, 7))
                reader = tree.reader()
                self.assertTrue(reader.current().ok)
                data = snapshot_at(T0, 8)
                data["members"] = disabled
                if written_at:
                    data["written_at"] = written_at
                text = json.dumps(data)
                if name == "deep nesting":
                    text = text[:-1] + ', "ignored": ' + "[" * 100_000 + "]" * 100_000 + "}"
                Path(tree.file + ".new").write_text(text, "utf-8")
                os.chmod(tree.file + ".new", 0o644)
                os.replace(tree.file + ".new", tree.file)
                tree.clock = T0 + 5_000
                first = reader.current()
                tree.clock = T0 + 5_001
                second = reader.current()
                # Python versions differ on how deep their JSON parser goes; either the new snapshot is read
                # (the member is disabled) or nothing is, but never the old one.
                for state in (first, second):
                    if state.ok:
                        self.assertEqual(state.snapshot.generation, 8, name)
                    else:
                        self.assertEqual(state.reason, "malformed", name)

    def test_an_ignored_integer_too_long_for_int_is_still_read(self):
        """JSON.parse reads any number; Python's int() refuses more than 4300 digits by default."""
        tree = Tree(self)
        text = json.dumps(snapshot_at(T0))[:-1] + ', "ignored": ' + "9" * 4301 + "}"
        Path(tree.file).write_text(text, "utf-8")
        os.chmod(tree.file, 0o644)
        self.assertTrue(tree.reader().current().ok)

    def test_a_lower_generation_than_one_already_seen_is_refused(self):
        tree = Tree(self)
        reader = tree.reader(recheck_ms=0)
        tree.write(snapshot_at(T0, 5))
        self.assertEqual(reader.current().snapshot.generation, 5)
        tree.write(snapshot_at(T0, 4))
        self.assertEqual(reader.current().reason, "rollback")
        tree.write(snapshot_at(T0, 5))
        self.assertEqual(reader.current().snapshot.generation, 5, "the same generation again is fine")
        tree.write(snapshot_at(T0, 6))
        tree.clock = T0 + 1
        self.assertEqual(reader.current().snapshot.generation, 6)

    def test_the_reader_needs_the_home_base_users_uid_and_it_is_never_root(self):
        with self.assertRaisesRegex(ValueError, "uid"):
            SnapshotReader(home_base_uid="1000")
        with self.assertRaisesRegex(ValueError, "uid"):
            SnapshotReader(home_base_uid=True)
        with self.assertRaisesRegex(ValueError, "never root"):
            SnapshotReader(home_base_uid=0)


if __name__ == "__main__":
    unittest.main()
