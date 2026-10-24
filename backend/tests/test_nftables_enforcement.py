"""Unit tests for Nftables Enforcement Backend (Task 6)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from security.enforcement.nftables import NftablesBackend


def test_nftables_dry_run_never_calls_subprocess() -> None:
    backend = NftablesBackend(dry_run=True)
    assert backend.dry_run is True

    with patch("subprocess.run") as mock_run:
        backend.init_table()
        assert backend.apply_block("198.51.100.50", ttl=300) is True
        assert len(backend.list_blocks()) == 1
        assert backend.remove_block("198.51.100.50") is True
        assert len(backend.list_blocks()) == 0

        # Subprocess must never be called in dry run mode
        mock_run.assert_not_called()


def test_nftables_live_exact_argument_lists() -> None:
    backend = NftablesBackend(dry_run=False)
    assert backend.dry_run is False

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        # 1. Initialize table
        backend.init_table()
        expected_init_calls = [
            ["nft", "add", "table", "inet", "volcano"],
            ["nft", "add", "set", "inet", "volcano", "blocked_ips", "{ type ipv4_addr; flags timeout; }"],
            ["nft", "add", "chain", "inet", "volcano", "input", "{ type filter hook input priority -10; policy accept; }"],
            ["nft", "add", "rule", "inet", "volcano", "input", "ip", "saddr", "@blocked_ips", "drop"],
        ]
        assert mock_run.call_count == 4
        for idx, expected_cmd in enumerate(expected_init_calls):
            actual_cmd = mock_run.call_args_list[idx][0][0]
            assert actual_cmd == expected_cmd

        mock_run.reset_mock()

        # 2. Apply block with TTL
        success = backend.apply_block("203.0.113.25", ttl=3600)
        assert success is True
        assert mock_run.call_count == 1
        expected_add_cmd = ["nft", "add", "element", "inet", "volcano", "blocked_ips", "{ 203.0.113.25 timeout 3600s }"]
        assert mock_run.call_args_list[0][0][0] == expected_add_cmd

        mock_run.reset_mock()

        # 3. Remove block
        success_remove = backend.remove_block("203.0.113.25")
        assert success_remove is True
        assert mock_run.call_count == 1
        expected_del_cmd = ["nft", "delete", "element", "inet", "volcano", "blocked_ips", "{ 203.0.113.25 }"]
        assert mock_run.call_args_list[0][0][0] == expected_del_cmd


def test_shell_true_never_used() -> None:
    backend = NftablesBackend(dry_run=False)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")

        backend.init_table()
        backend.apply_block("198.51.100.99")
        backend.remove_block("198.51.100.99")

        assert mock_run.call_count > 0
        for call in mock_run.call_args_list:
            # Assert shell=False and never shell=True
            kwargs = call[1]
            assert kwargs.get("shell") is False
            assert "shell=True" not in str(call)


def test_invalid_ips_rejected() -> None:
    backend = NftablesBackend(dry_run=False)

    invalid_inputs = [
        "not-an-ip",
        "999.999.999.999",
        "192.168.1.1; rm -rf /",
        "10.0.0.1 && cat /etc/passwd",
        "",
        "   ",
        "2001:xyz::1",
    ]

    with patch("subprocess.run") as mock_run:
        for bad_ip in invalid_inputs:
            with pytest.raises(ValueError):
                backend.apply_block(bad_ip)

        # No subprocess calls made
        mock_run.assert_not_called()


def test_allowlisted_ips_rejected() -> None:
    backend = NftablesBackend(dry_run=False)

    allowlisted = [
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    ]

    with patch("subprocess.run") as mock_run:
        for immune_ip in allowlisted:
            result = backend.apply_block(immune_ip)
            assert result is False

        mock_run.assert_not_called()
        assert len(backend.list_blocks()) == 0


def test_snapshot_and_restore() -> None:
    backend = NftablesBackend(dry_run=True)

    backend.apply_block("203.0.113.1")
    backend.apply_block("203.0.113.2")
    assert len(backend.list_blocks()) == 2

    # Take snapshot
    snap = backend.snapshot()
    assert snap["blocked_ips"] == ["203.0.113.1", "203.0.113.2"]

    # Mutate state: add 203.0.113.3 and remove 203.0.113.1
    backend.apply_block("203.0.113.3")
    backend.remove_block("203.0.113.1")
    assert sorted([b["ip"] for b in backend.list_blocks()]) == ["203.0.113.2", "203.0.113.3"]

    # Restore from snapshot
    assert backend.restore(snap) is True
    assert sorted([b["ip"] for b in backend.list_blocks()]) == ["203.0.113.1", "203.0.113.2"]
