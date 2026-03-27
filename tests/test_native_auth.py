from __future__ import annotations

import pytest

import won_server


def test_native_login_requires_explicit_account_creation_and_binds_cd_key(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
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
            cd_key="NYX7 ZEC9 FYZ6 GUX8 4253",
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
        assert updated["native_cd_key"] == "NYX7ZEC9FYZ6GUX84253"
        assert updated["native_login_key"] == "install-b"

        with pytest.raises(ValueError, match="cd_key_mismatch"):
            state.login_native(
                "Zero",
                "hunter2",
                cd_key="PYL8-GUD4-BET3-MEX9-6624",
                create_account=False,
            )
    finally:
        store.close()


def test_native_login_rejects_missing_cd_key(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_missing_cd_key.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
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
        store.close()


def test_native_login_rejects_invalid_cd_key(tmp_path) -> None:
    db_path = tmp_path / "won_native_auth_invalid_cd_key.db"
    store = won_server.StateStore(str(db_path))
    state = won_server.WONLikeState(store)

    try:
        with pytest.raises(ValueError, match="invalid_cd_key"):
            state.login_native(
                "InvalidKeyUser",
                "pw",
                cd_key="NYX7-ZEC9-FYZ6-GUX8-4252",
                create_account=True,
            )
    finally:
        store.close()
