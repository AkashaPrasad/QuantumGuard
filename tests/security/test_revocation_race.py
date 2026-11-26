"""Compare transaction ordering, never wall-clock request start times."""


def test_revoked_device_gets_no_slot_under_concurrent_release(security_case):
    case = security_case("revocation_race")
    assert case.act("slot_before_race").status_code == 200
    race = case.race_release_and_revoke(workers=8)
    assert race.revoke_committed is True
    assert len(race.releases) >= 8
    after = [release for release in race.releases if release.decision_index >= race.revoke_commit_index]
    assert after, "Race must include operations ordered after revoke commits."
    for release in after:
        assert release.status_code in (401, 403)
        assert release.contains_key_material is False
    assert case.observe("active_sessions_for_revoked_device") == 0
    assert case.observe("slots_for_revoked_device") == 0
    assert case.act("unrelated_device_slot").status_code == 200
