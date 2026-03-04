"""Tests for capture module."""
import json
import tempfile
from pathlib import Path

import pytest

from ir_sinkhole.capture import (
    _parse_ss_tcp,
    get_active_tcp_connections,
    unique_remote_endpoints,
)


def test_parse_ss_tcp_empty():
    assert _parse_ss_tcp("") == []
    assert _parse_ss_tcp("State  Recv-Q Send-Q  Local  Peer\n") == []


def test_parse_ss_tcp_established():
    out = (
        "ESTAB  0  0  192.168.1.5:45678  66.235.175.117:1244  users:((\"node\",pid=1234,fd=5))\n"
    )
    rows = _parse_ss_tcp(out)
    assert len(rows) == 1
    assert rows[0]["remote_ip"] == "66.235.175.117"
    assert rows[0]["remote_port"] == "1244"
    assert rows[0]["local_port"] == "45678"
    assert rows[0].get("pid") == 1234


def test_unique_remote_endpoints():
    conns = [
        {"remote_ip": "1.2.3.4", "remote_port": "443"},
        {"remote_ip": "1.2.3.4", "remote_port": "443"},
        {"remote_ip": "5.6.7.8", "remote_port": "80"},
    ]
    out = unique_remote_endpoints(conns)
    assert out == [("1.2.3.4", "443"), ("5.6.7.8", "80")]
