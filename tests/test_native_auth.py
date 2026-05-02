from __future__ import annotations

import time

import pytest

from product_profile import CATACLYSM_PRODUCT_PROFILE, HOMEWORLD_PRODUCT_PROFILE
import won_server


def _clear_auth_rate_limits() -> None:
    won_server._login_attempts.clear()
    won_server._native_key_write_attempts.clear()


def test_native_login_requires_explicit_account_creation_and_rebinds_cd_key_after_successful_password_check(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        with pytest.raises(ValueError, match="create_account_required"):
            state.login_native(
                "Zero",
                "hunter2",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                create_account=False,
            )

        created = state.login_native(
            "Zero",
            "hunter2",
            cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
            login_key="install-a",
            create_account=True,
        )
        assert created["created"] is True
        assert created["cd_key_bound"] is True

        row = store.conn.execute(
            "SELECT native_cd_key, native_login_key FROM users WHERE username=?",
            ("Zero",),
        ).fetchone()
        assert row is not None
        assert row["native_cd_key"] == "NYX7ZEC9FYZ6GUX84253"
        assert row["native_login_key"] == "install-a"

        rebound = state.login_native(
            "Zero",
            "hunter2",
            cd_key="PYL8-GUD4-BET3-MEX9-6624",
            login_key="install-b",
            create_account=False,
        )
        assert rebound["created"] is False
        assert rebound["cd_key_bound"] is True
        assert rebound["binding_changed"] is True

        updated = store.conn.execute(
            "SELECT native_cd_key, native_login_key FROM users WHERE username=?",
            ("Zero",),
        ).fetchone()
        assert updated is not None
        assert updated["native_cd_key"] == "PYL8GUD4BET3MEX96624"
        assert updated["native_login_key"] == "install-b"
    finally:
        _clear_auth_rate_limits()
        store.close()


@pytest.mark.parametrize(
    ("profile", "expected_root", "expected_valid_versions"),
    [
        (
            HOMEWORLD_PRODUCT_PROFILE,
            "/Homeworld",
            "HomeworldValidVersions",
        ),
        (
            CATACLYSM_PRODUCT_PROFILE,
            "/Cataclysm",
            "CataclysmValidVersions",
        ),
    ],
)
def test_backend_bootstrap_uses_selected_product_profile(
    tmp_path,
    profile,
    expected_root: str,
    expected_valid_versions: str,
) -> None:
    db_path = tmp_path / ("won_backend_" + profile.key + ".db")
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store, product_profile=profile)

    try:
        assert expected_root in state.directory
        assert profile.titan_servers_path in state.directory
        assert expected_root in state.protected_paths
        assert profile.titan_servers_path in state.protected_paths

        titan = state.directory[profile.titan_servers_path]
        assert expected_valid_versions in titan
        assert titan[expected_valid_versions]["payload"]["versions"] == list(
            profile.backend_valid_versions
        )
    finally:
        store.close()


def test_native_login_uses_product_specific_cd_key_validation(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_cataclysm.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store, product_profile=CATACLYSM_PRODUCT_PROFILE)

    try:
        _clear_auth_rate_limits()
        created = state.login_native(
            "Beast",
            "hunter2",
            cd_key="GAF6-CAB4-SEX5-ZYL6-2622",
            create_account=True,
        )
        assert created["created"] is True
        assert created["cd_key_bound"] is True

        with pytest.raises(ValueError, match="invalid_cd_key"):
            state.login_native(
                "WrongGameKey",
                "hunter2",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                create_account=True,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()


def test_native_login_rejects_missing_cd_key(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_missing_cd_key.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        with pytest.raises(ValueError, match="missing_cd_key"):
            state.login_native(
                "MissingKeyUser",
                "pw",
                cd_key="",
                create_account=True,
            )

        state.login_native(
            "BoundUser",
            "pw",
            cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
            create_account=True,
        )

        with pytest.raises(ValueError, match="missing_cd_key"):
            state.login_native(
                "BoundUser",
                "pw",
                cd_key="",
                create_account=False,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()


def test_native_login_rejects_invalid_cd_key(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_invalid_cd_key.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        with pytest.raises(ValueError, match="invalid_cd_key"):
            state.login_native(
                "InvalidKeyUser",
                "pw",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4252",
                create_account=True,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()


def test_native_login_does_not_rotate_password_for_existing_accounts(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_existing_password.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        state.login_native(
            "Zero",
            "hunter2",
            cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
            create_account=True,
        )

        relogin = state.login_native(
            "Zero",
            "hunter2",
            cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
            new_password="rotate-me",
            create_account=False,
        )
        assert relogin["created"] is False
        assert relogin["binding_changed"] is False

        state.login_native(
            "Zero",
            "hunter2",
            cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
            create_account=False,
        )

        with pytest.raises(ValueError, match="invalid_credentials"):
            state.login_native(
                "Zero",
                "rotate-me",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                create_account=False,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()


def test_native_login_rate_limits_repeated_account_creation_key_writes_per_ip(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_rate_limited.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        client_ip = "1.2.3.4"
        for idx in range(won_server.MAX_NATIVE_KEY_WRITES):
            result = state.login_native(
                f"User{idx}",
                "pw",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                client_ip=client_ip,
                create_account=True,
            )
            assert result["created"] is True

        with pytest.raises(ValueError, match="rate_limited"):
            state.login_native(
                "BlockedUser",
                "pw",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                client_ip=client_ip,
                create_account=True,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()


def test_native_login_rate_limits_first_time_cd_key_binding_after_empty_account(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_binding_rate_limit.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        _clear_auth_rate_limits()
        state.create_user("Zero", "hunter2")
        won_server._native_key_write_attempts["1.2.3.4"] = [
            time.time()
            for _ in range(won_server.MAX_NATIVE_KEY_WRITES)
        ]

        with pytest.raises(ValueError, match="rate_limited"):
            state.login_native(
                "Zero",
                "hunter2",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4253",
                client_ip="1.2.3.4",
                create_account=False,
            )
    finally:
        _clear_auth_rate_limits()
        store.close()
