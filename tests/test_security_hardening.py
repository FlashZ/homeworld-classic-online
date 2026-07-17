from __future__ import annotations

import hashlib

from connection_limits import ConnectionLimiter
import won_server


def test_new_passwords_use_salted_pbkdf2_and_legacy_logins_upgrade(tmp_path) -> None:
    store = won_server.StateStore(str(tmp_path / "passwords.db"))
    state = won_server.WONLikeState(store)
    try:
        state.create_user("new-user", "correct horse battery staple")
        stored = store.conn.execute(
            "SELECT password_hash FROM users WHERE username=?", ("new-user",)
        ).fetchone()["password_hash"]
        assert stored.startswith("pbkdf2_sha256$")
        assert state._verify_password("correct horse battery staple", stored) == (True, False)

        legacy = hashlib.sha256(b"legacy-password").hexdigest()
        store.conn.execute(
            "INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)",
            ("legacy-user", legacy, 0),
        )
        store.conn.commit()

        state.login("legacy-user", "legacy-password")
        upgraded = store.conn.execute(
            "SELECT password_hash FROM users WHERE username=?", ("legacy-user",)
        ).fetchone()["password_hash"]
        assert upgraded.startswith("pbkdf2_sha256$")
        assert upgraded != legacy
        assert state._verify_password("legacy-password", upgraded) == (True, False)
        assert state._verify_password("wrong-password", upgraded) == (False, False)
    finally:
        store.close()


def test_connection_limiter_caps_global_and_per_ip_usage() -> None:
    limiter = ConnectionLimiter(max_connections=2, max_per_ip=1)
    assert limiter.acquire("203.0.113.10") is True
    assert limiter.acquire("203.0.113.10") is False
    assert limiter.acquire("203.0.113.11") is True
    assert limiter.acquire("203.0.113.12") is False
    assert limiter.active == 2

    limiter.release("203.0.113.10")
    assert limiter.acquire("203.0.113.12") is True
    assert limiter.active == 2
