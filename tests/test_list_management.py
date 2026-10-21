"""List management on disk (app/list_management.py, app/storage.py)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app import list_management as lm
from app import storage
from app.storage import FULL_LIST, IDENTIFIER_LIST, TOKEN_LIST, CorruptList, ListNotFound
from tests.conftest import MDL, PID
from tests.strict import check_list_files, jwt_status


def ref(info):
    """``(list_id, idx)`` of a take result."""
    return info["status_list"]["uri"].rsplit("/", 1)[1], info["status_list"]["idx"]


def dirs(country, doctype, list_id):
    return (storage.list_dir(TOKEN_LIST, country, doctype, list_id), storage.list_dir(IDENTIFIER_LIST, country, doctype, list_id))


class TestTake:
    def test_writes_every_file_with_the_uris(self, configuration):
        info = lm.take("FC", PID, "2099-01-01")
        list_id, idx = ref(info)
        token_dir, identifier_dir = dirs("FC", PID, list_id)
        check_list_files(token_dir, identifier_dir)
        stored = json.loads((token_dir / FULL_LIST).read_text())
        # issue 4: the URIs are in the very first dump
        assert stored["status_list_uri"] == info["status_list"]["uri"]
        assert stored["identifier_list_uri"] == info["identifier_list"]["uri"]
        assert stored["expires"] == "2099-01-01"
        assert info["identifier_list"]["id"] == str(idx)
        assert storage.current_list_id("FC", PID) == list_id

    def test_only_the_published_files_are_world_readable(self, configuration):
        token_dir, identifier_dir = dirs("FC", PID, ref(lm.take("FC", PID, "2099-01-01"))[0])
        published = {token_dir: {"token_status_list.jwt", "token_status_list.cwt"},
                     identifier_dir: {"identifier_list.cwt"}}
        for directory, names in published.items():
            for f in directory.iterdir():
                expected = storage.PUBLISHED_MODE if f.name in names else storage.PRIVATE_MODE
                assert oct(f.stat().st_mode & 0o777) == oct(expected), f
        current = storage.state_dir("FC", PID) / "current.json"
        assert oct(current.stat().st_mode & 0o777) == oct(storage.PRIVATE_MODE)

    def test_take_on_an_existing_list_does_not_resign(self):
        """Taking an index changes no status: the published files stay as they are."""
        list_id, _ = ref(lm.take("FC", PID, "2099-01-01"))
        token_dir, identifier_dir = dirs("FC", PID, list_id)
        published = {p.name: p.read_bytes() for d in (token_dir, identifier_dir) for p in d.iterdir() if p.suffix != ".json"}
        lm.take("FC", PID, "2100-01-01")
        assert {p.name: p.read_bytes() for d in (token_dir, identifier_dir) for p in d.iterdir() if p.suffix != ".json"} == published
        assert storage.load_entry("FC", PID, list_id)["expires"] == "2100-01-01"

    def test_same_list_until_full(self):
        first = ref(lm.take("FC", PID, "2099-01-01"))
        second = ref(lm.take("FC", PID, "2099-01-01"))
        assert first[0] == second[0] and first[1] != second[1]

    def test_expiry_follows_the_latest_credential(self):
        list_id, _ = ref(lm.take("FC", PID, "2099-01-01"))
        lm.take("FC", PID, "2098-01-01")
        lm.take("FC", PID, "2100-01-01")
        assert storage.load_entry("FC", PID, list_id)["expires"] == "2100-01-01"

    def test_survives_a_restart(self):
        """issue 14: the current list is on disk, not in a process."""
        first = ref(lm.take("FC", PID, "2099-01-01"))
        assert ref(lm.take("FC", PID, "2099-01-01"))[0] == first[0]

    def test_full_list_starts_a_new_one_and_keeps_the_others(self, configuration):
        """issues 2 and 11: only the full list is replaced; index and URI match."""
        configuration["token_status_list_size"] = 8
        other = ref(lm.take("LU", MDL, "2099-01-01"))
        same_country = ref(lm.take("FC", MDL, "2099-01-01"))
        taken = [ref(lm.take("FC", PID, "2099-01-01")) for _ in range(17)]
        lists = sorted({list_id for list_id, _ in taken})
        assert len(lists) == 3
        assert len(set(taken)) == 17
        for list_id in lists:
            indices = sorted(i for l, i in taken if l == list_id)
            assert set(indices) <= set(range(8))
        assert storage.current_list_id("LU", MDL) == other[0]
        assert storage.current_list_id("FC", MDL) == same_country[0]
        assert ref(lm.take("LU", MDL, "2099-01-01"))[0] == other[0]

    def test_new_lists_do_not_share_identifiers(self):
        """issue 3."""
        a = storage.new_entry("FC", PID)
        b = storage.new_entry("LU", PID)
        assert a["identifier_list"] is not b["identifier_list"]
        assert a["rand"] != b["rand"]

    def test_unreadable_current_list_starts_a_new_one(self):
        list_id, _ = ref(lm.take("FC", PID, "2099-01-01"))
        (dirs("FC", PID, list_id)[0] / FULL_LIST).write_text("{broken")
        assert ref(lm.take("FC", PID, "2099-01-01"))[0] != list_id

    def test_pointer_to_a_removed_list(self):
        storage.set_current_list_id("FC", PID, "00000000-0000-0000-0000-000000000000")
        assert ref(lm.take("FC", PID, "2099-01-01"))[0] != "00000000-0000-0000-0000-000000000000"


class TestRevoke:
    def test_sets_both_lists(self):
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        lm.revoke("FC", PID, list_id, idx)
        token_dir, identifier_dir = dirs("FC", PID, list_id)
        check_list_files(token_dir, identifier_dir)
        assert jwt_status(token_dir, idx) == 1
        assert lm.read_status(TOKEN_LIST, "FC", PID, list_id, idx) == 1
        assert lm.read_status(IDENTIFIER_LIST, "FC", PID, list_id, idx) == 1

    def test_takes_after_a_revocation(self):
        """issue 1: was AttributeError on the second take."""
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        lm.revoke("FC", PID, list_id, idx)
        for _ in range(3):
            assert ref(lm.take("FC", PID, "2099-01-01"))[0] == list_id
        assert lm.read_status(TOKEN_LIST, "FC", PID, list_id, idx) == 1

    def test_revoking_twice(self):
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        lm.revoke("FC", PID, list_id, idx)
        lm.revoke("FC", PID, list_id, idx)
        assert lm.read_status(TOKEN_LIST, "FC", PID, list_id, idx) == 1

    def test_old_list_after_rollover(self, configuration):
        configuration["token_status_list_size"] = 8
        first_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        for _ in range(8):
            lm.take("FC", PID, "2099-01-01")
        assert storage.current_list_id("FC", PID) != first_id
        lm.revoke("FC", PID, first_id, idx)
        assert lm.read_status(TOKEN_LIST, "FC", PID, first_id, idx) == 1

    @pytest.mark.parametrize("idx", [-1, 10000, 10**9])
    def test_index_out_of_range(self, idx):
        """issue 12: -1 used to revoke the last entry."""
        list_id, _ = ref(lm.take("FC", PID, "2099-01-01"))
        with pytest.raises(lm.IndexOutOfRange):
            lm.revoke("FC", PID, list_id, idx)
        with pytest.raises(lm.IndexOutOfRange):
            lm.read_status(TOKEN_LIST, "FC", PID, list_id, idx)
        assert lm.read_status(TOKEN_LIST, "FC", PID, list_id, 9999) == 0

    def test_unknown_list(self):
        with pytest.raises(ListNotFound):
            lm.revoke("FC", PID, "00000000-0000-0000-0000-000000000000", 1)

    def test_corrupt_list(self):
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        (dirs("FC", PID, list_id)[0] / FULL_LIST).write_text('{"token_status_list": 1}')
        with pytest.raises(CorruptList):
            lm.revoke("FC", PID, list_id, idx)

    def test_read_status_unknown_kind(self):
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        with pytest.raises(ValueError, match="unknown list kind"):
            lm.read_status("other", "FC", PID, list_id, idx)


class TestStorage:
    def test_atomic_write_replaces_in_one_step(self, tmp_path):
        target = tmp_path / "a" / "file"
        storage.atomic_write(target, b"longer content")
        storage.atomic_write(target, "short")
        assert target.read_bytes() == b"short"  # issue 7: no tail of the longer file
        assert oct(target.stat().st_mode & 0o777) == oct(storage.PRIVATE_MODE)
        assert [p.name for p in target.parent.iterdir()] == ["file"]

    def test_atomic_write_failure_keeps_the_old_file(self, tmp_path, monkeypatch):
        target = tmp_path / "file"
        storage.atomic_write(target, b"old")

        def broken_replace(*_):
            raise OSError("disk full")

        monkeypatch.setattr(storage.os, "replace", broken_replace)
        with pytest.raises(OSError):
            storage.atomic_write(target, b"new")
        assert target.read_bytes() == b"old"
        assert [p.name for p in tmp_path.iterdir()] == ["file"]

    def test_signing_failure_leaves_published_files(self, monkeypatch):
        """issue 9: a failing formatter used to leave an empty file behind."""
        list_id, idx = ref(lm.take("FC", PID, "2099-01-01"))
        token_dir, identifier_dir = dirs("FC", PID, list_id)
        before = {p.name: p.read_bytes() for d in (token_dir, identifier_dir) for p in d.iterdir()}

        def broken(*_):
            raise RuntimeError("signer unavailable")

        monkeypatch.setattr(storage, "identifier_list_cwt_format", broken)
        with pytest.raises(RuntimeError):
            lm.revoke("FC", PID, list_id, idx)
        after = {p.name: p.read_bytes() for d in (token_dir, identifier_dir) for p in d.iterdir()}
        assert after == before

    def test_old_lists_without_uris_get_them(self):
        """Lists written by the first dump of older versions had no URIs."""
        list_id, _ = ref(lm.take("FC", PID, "2099-01-01"))
        path = dirs("FC", PID, list_id)[0] / FULL_LIST
        data = json.loads(path.read_text())
        del data["status_list_uri"], data["identifier_list_uri"]
        data["identifier_list"]["identifiers"] = {"7": {}}
        path.write_text(json.dumps(data))
        entry = storage.load_entry("FC", PID, list_id)
        assert entry["status_list_uri"].endswith(f"/token_status_list/FC/{PID}/{list_id}")
        assert entry["identifier_list"]["identifiers"] == {"7": {}}

    def test_pointer(self):
        assert storage.current_list_id("FC", PID) is None
        storage.set_current_list_id("FC", PID, "x")
        assert storage.current_list_id("FC", PID) == "x"
        storage.set_current_list_id("FC", PID, None)
        storage.set_current_list_id("FC", PID, None)
        assert storage.current_list_id("FC", PID) is None

    def test_file_lock_non_blocking(self, tmp_path):
        with storage.file_lock(tmp_path / "l") as held:
            assert held
            # A second open file description in the same process conflicts with flock.
            with storage.file_lock(tmp_path / "l", blocking=False) as again:
                assert again is False
