"""Build-plan 13.2 claims. Scenario setup uses production crypto and HTTP clients."""

import pytest


def deny(response, status, code, reason=None):
    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == code
    if reason is not None:
        assert error["reason"] == reason
    assert response.headers.get("QG-Request-Id")


def client_refuses(result):
    assert result.returncode != 0
    assert result.plaintext_written is False


def test_revoked_device_cannot_start_session(security_case):
    case = security_case("revoked_session")
    assert case.act("valid_session").status_code == 200
    assert case.act("revoke").status_code == 200
    # The contract deliberately gives revoked/unknown starts the same shape.
    start = case.act("revoked_start")
    assert start.status_code == 200
    deny(case.act("revoked_finish"), 403, "QG_DENY_REVOKED")


def test_revoked_devices_existing_session_dies_in_same_transaction(security_case):
    case = security_case("revoked_existing_session")
    assert case.act("slot_before").status_code == 200
    assert case.act("revoke").status_code == 200
    response = case.act("slot_after_same_session")
    assert response.status_code in (401, 403)
    assert response.json()["error"]["code"] in ("QG_NO_SESSION", "QG_DENY_REVOKED")
    assert case.observe("active_sessions_for_revoked_device") == 0
    assert case.observe("slots_for_revoked_device") == 0


@pytest.mark.parametrize("target", ["file", "device"])
def test_slot_moved_to_another_context_fails(security_case, target):
    case = security_case("slot_context")
    assert case.act("open_original").returncode == 0
    client_refuses(case.act("open_slot_moved_to_" + target))


@pytest.mark.parametrize("mutation", ["reordered", "truncated"])
def test_chunk_reordered_or_truncated_fails(security_case, mutation):
    case = security_case("chunk_integrity")
    assert case.act("open_original").returncode == 0
    client_refuses(case.act("open_" + mutation))


def test_ciphertext_bit_flip_fails(security_case):
    case = security_case("chunk_integrity")
    assert case.act("open_original").returncode == 0
    client_refuses(case.act("open_bit_flipped"))


def test_wrong_aad_fails(security_case):
    case = security_case("chunk_integrity")
    assert case.act("open_original").returncode == 0
    client_refuses(case.act("open_wrong_aad"))


def test_older_directory_rejected_by_client(security_case):
    case = security_case("directory_rollback")
    assert case.act("accept_new_directory").returncode == 0
    client_refuses(case.act("accept_old_directory"))


def test_older_directory_rejected_by_server(security_case):
    case = security_case("directory_rollback")
    case.act("advance_past_epoch_grace")
    deny(case.act("commit_old_epoch"), 409, "QG_STALE_EPOCH")
    assert case.observe("pending_version_committed") is False


def test_manifest_naming_unauthorized_recipient_rejected(security_case):
    case = security_case("unauthorized_manifest_recipient")
    deny(case.act("commit"), 403, "QG_DENY_POLICY", "recipient_not_allowed")
    assert case.observe("unauthorized_recipient_has_slot") is False


def test_replayed_request_rejected_and_session_ended(security_case):
    case = security_case("request_replay")
    assert case.act("original").status_code == 200
    deny(case.act("exact_replay"), 401, "QG_REPLAY")
    deny(case.act("fresh_sequence_same_session"), 401, "QG_NO_SESSION")


def test_sequence_gap_tolerated_but_regression_rejected(security_case):
    case = security_case("sequence_gap")
    assert case.act("sequence_1").status_code == 200
    assert case.act("sequence_100").status_code == 200
    deny(case.act("sequence_99"), 401, "QG_REPLAY")


def test_expired_lease_stops_download_mid_file(security_case, clock):
    case = security_case("lease_expiry")
    assert case.act("slot").status_code == 200
    assert case.act("chunk_0").status_code == 200
    clock.advance(case.observe("lease_seconds") + 1)
    deny(case.act("chunk_1"), 403, "QG_LEASE_EXPIRED")


def test_expired_invite_rejected(security_case, clock):
    case = security_case("expired_invite")
    clock.advance(case.observe("invite_ttl_seconds") + 1)
    deny(case.act("enroll_start"), 400, "QG_INVALID_INPUT", "invite_invalid")


def test_invite_reused_rejected(security_case):
    case = security_case("reused_invite")
    assert case.act("first_enroll").status_code == 200
    deny(case.act("second_enroll_start"), 400, "QG_INVALID_INPUT", "invite_invalid")


@pytest.mark.parametrize("proof", ["kem", "signing"])
def test_enrollment_without_key_possession_proof_rejected(security_case, proof):
    case = security_case("missing_enrollment_proof")
    deny(case.act("finish_without_" + proof + "_proof"), 400, "QG_BAD_SIGNATURE", "proof_failed")
    assert case.observe("new_device_published") is False


def test_self_approval_of_sensitive_change_rejected(security_case):
    case = security_case("self_approval")
    deny(case.act("requester_approves"), 403, "QG_DENY_POLICY", "self_approval")
    deny(case.act("target_approves"), 403, "QG_DENY_POLICY", "self_approval")
    assert case.observe("change_applied") is False


def test_privilege_without_signed_record_raises_qg_r005(security_case):
    case = security_case("unsigned_privilege")
    case.act("inject_unsigned_role_at_identity_source")
    assert case.act("sensitive_slot").status_code == 403
    assert case.observe("alert_rule_ids").count("QG-R005") >= 1
    assert case.observe("target_identity_quarantined") is True
    assert case.act("unrelated_identity_slot").status_code == 200


def test_decoy_touch_raises_qg_r004_and_quarantines_device(security_case):
    case = security_case("decoy_touch")
    assert case.act("touch_decoy").status_code == 403
    assert "QG-R004" in case.observe("alert_rule_ids")
    deny(case.act("same_device_slot"), 403, "QG_QUARANTINED")
    assert case.act("unrelated_device_slot").status_code == 200


def test_unknown_suite_rejected(security_case):
    case = security_case("unknown_suite")
    deny(case.act("enroll_with_unknown_suite"), 400, "QG_BAD_SUITE")


@pytest.mark.parametrize("route", ["metadata", "slot", "chunk", "share", "delete", "recover"])
def test_other_users_object_ids_return_not_found_without_existence_leak(security_case, route):
    case = security_case("object_isolation")
    hidden = case.act("hidden_" + route)
    absent = case.act("absent_" + route)
    deny(hidden, 404, "QG_NOT_FOUND")
    deny(absent, 404, "QG_NOT_FOUND")
    for field in ("code", "message", "reason"):
        assert hidden.json()["error"][field] == absent.json()["error"][field]


def test_log_byte_flip_detected_by_offline_verifier(security_case):
    case = security_case("proof_bundle_integrity")
    assert case.act("verify_original").returncode == 0
    client_refuses(case.act("verify_log_byte_flip"))


@pytest.mark.parametrize("signature", ["ed25519", "mldsa"])
def test_checkpoint_with_one_bad_signature_rejected(security_case, signature):
    case = security_case("proof_bundle_integrity")
    assert case.act("verify_original").returncode == 0
    client_refuses(case.act("verify_bad_" + signature + "_checkpoint_signature"))


def test_policy_engine_down_means_deny_without_key_release(security_case):
    case = security_case("policy_outage")
    assert case.act("slot_before_outage").status_code == 200
    case.act("disable_policy_engine")
    deny(case.act("slot_during_outage"), 503, "QG_UNAVAILABLE_FAIL_CLOSED")
    assert case.observe("release_count_during_outage") == 0


def test_no_generated_secret_appears_in_any_log_line(security_case):
    case = security_case("secret_logging")
    case.act("exercise_full_workflow_with_random_canaries")
    secrets = case.observe("generated_secret_canaries")
    logs = case.observe("all_log_lines")
    assert secrets, "Scenario must exercise real random credentials and private keys."
    assert logs, "Scenario must capture stdout, application and security-event logs."
    # Never place secret bytes in pytest's assertion diff or failure artifacts.
    leaked = any(secret in line for secret in secrets for line in logs)
    assert not leaked, "A generated credential or key appeared in captured logs."


def test_server_database_copy_alone_cannot_decrypt_file(security_case):
    case = security_case("database_copy")
    assert case.act("legitimate_client_open").returncode == 0
    result = case.act("attempt_decryption_with_database_and_public_artifacts")
    assert result.attempted is True
    assert result.private_keys_available is False
    assert result.plaintext_recovered is False


def test_recovery_slot_unusable_without_two_independent_approvals(security_case):
    case = security_case("recovery_approval")
    deny(case.act("recover_zero_approvals"), 403, "QG_DENY_POLICY")
    assert case.act("first_independent_approval").status_code == 200
    deny(case.act("recover_one_approval"), 403, "QG_DENY_POLICY")
    duplicate = case.act("same_person_second_device_approval")
    assert duplicate.status_code in (403, 409)
    assert case.act("second_independent_approval").status_code == 200
    assert case.act("recover_two_approvals").status_code == 200
