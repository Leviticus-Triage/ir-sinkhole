"""Tests for replay module."""
from pathlib import Path

import pytest

from ir_sinkhole.replay import build_replay_db, load_replay_db, save_replay_db


def test_build_replay_db_empty_file(tmp_path):
    pcap = tmp_path / "empty.pcap"
    pcap.write_bytes(b"")
    assert build_replay_db(pcap) == {}


def test_save_load_replay_db(tmp_path):
    db = {("1.2.3.4", "443"): [b"HTTP/1.1 200 OK\r\n\r\n", b"body"]}
    path = tmp_path / "replay.json"
    save_replay_db(db, path)
    loaded = load_replay_db(path)
    assert loaded == db
