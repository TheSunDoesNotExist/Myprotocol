"""Regression checks promoted from the protocol audit as issues are fixed."""

import unittest

import audit_checks


def load_tests(loader, tests, pattern):
    return unittest.TestSuite([
        audit_checks.NetworkAudit("test_quic_reassembly_is_bounded_before_access_key"),
        audit_checks.NetworkAudit("test_unauthenticated_udp_close_preserves_working_tcp_session"),
        audit_checks.StateAudit("test_old_generation_cannot_win_during_ready_ok_drain"),
        audit_checks.StateAudit("test_client_ignores_superseded_ready_ok"),
        audit_checks.NetworkAudit("test_quic_peer_without_access_key_cannot_keep_handshake_slot"),
        audit_checks.StateAudit("test_failed_session_resets_application_instead_of_clean_eof"),
        audit_checks.StateAudit("test_rejected_local_connection_is_reset"),
        audit_checks.StateAudit("test_initial_connection_does_not_wait_for_alternative_probes"),
        audit_checks.StateAudit("test_stalled_stream_does_not_block_other_stream_or_ack"),
        audit_checks.NetworkAudit("test_private_alpn_removed_but_sni_remains_visible_without_ech"),
    ])
