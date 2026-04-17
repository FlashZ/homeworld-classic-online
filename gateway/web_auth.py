from __future__ import annotations

from html import escape
import hashlib
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode


@dataclass(frozen=True)
class _IssuedCode:
    product: str
    username: str
    return_to: str
    issued_at: float
    expires_at: float


class GatewayWebAuthBridge:
    def __init__(
        self,
        db_paths: dict[str, str | Path],
        default_product: str,
        shared_secret: str,
        code_ttl_seconds: float,
    ) -> None:
        if not db_paths:
            raise ValueError("missing_db_paths")

        self.db_paths = {str(product): str(path) for product, path in db_paths.items()}
        self.default_product = str(default_product or next(iter(self.db_paths)))
        self.shared_secret = str(shared_secret)
        self.code_ttl_seconds = float(code_ttl_seconds)
        self._codes: dict[str, _IssuedCode] = {}
        self._lock = threading.Lock()

    @staticmethod
    def hash_password(password: str) -> str:
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def _resolve_product(self, product: str) -> str:
        resolved = str(product or self.default_product)
        if resolved not in self.db_paths:
            raise ValueError("unknown_product")
        return resolved

    def start_login(
        self,
        product: str,
        username: str,
        password: str,
        return_to: str,
    ) -> dict[str, Any]:
        resolved_product = self._resolve_product(product)
        db_path = Path(self.db_paths[resolved_product])
        db_path.parent.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    native_cd_key TEXT,
                    native_login_key TEXT
                )
                """
            )
            row = conn.execute(
                "SELECT password_hash FROM users WHERE username = ?",
                (str(username),),
            ).fetchone()
        finally:
            conn.close()

        if row is None or self.hash_password(password) != str(row[0]):
            raise ValueError("invalid_credentials")

        now = time.time()
        code = secrets.token_urlsafe(24)
        record = _IssuedCode(
            product=resolved_product,
            username=str(username),
            return_to=str(return_to),
            issued_at=now,
            expires_at=now + self.code_ttl_seconds,
        )
        with self._lock:
            self._codes[code] = record

        return {
            "code": code,
            "product": record.product,
            "username": record.username,
            "return_to": record.return_to,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        }

    def render_login_page(
        self,
        *,
        product: str,
        return_to: str,
        error: str = "",
    ) -> bytes:
        form_query = urlencode(
            {
                "product": str(product or self.default_product),
                "return_to": str(return_to or ""),
            }
        )
        error_html = f'<p class="error">{escape(error)}</p>' if error else ""
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WON Sign In</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #08111f;
      --panel: #0d1728;
      --border: #2a3953;
      --text: #eff4ff;
      --muted: #8ea1bf;
      --accent: #f0b66b;
      --accent-2: #5fa0ff;
      --danger: #ff8f8f;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      background: radial-gradient(circle at top, #12213a 0, var(--bg) 55%);
      color: var(--text);
      font-family: Inter, Segoe UI, Helvetica, Arial, sans-serif;
      display: grid;
      place-items: center;
      padding: 32px;
    }}
    main {{
      width: min(520px, 100%);
      background: linear-gradient(180deg, rgba(13, 23, 40, 0.96), rgba(8, 17, 31, 0.96));
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 28px;
      box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
    }}
    h1 {{ margin: 0 0 8px; font-size: 28px; }}
    p {{ color: var(--muted); line-height: 1.5; }}
    .error {{
      color: var(--danger);
      margin: 16px 0 0;
      padding: 12px 14px;
      border: 1px solid rgba(255, 143, 143, 0.4);
      border-radius: 10px;
      background: rgba(255, 143, 143, 0.08);
    }}
    form {{ display: grid; gap: 14px; margin-top: 22px; }}
    label {{ display: grid; gap: 8px; font-size: 14px; color: var(--muted); }}
    input {{
      width: 100%;
      padding: 12px 14px;
      border-radius: 10px;
      border: 1px solid var(--border);
      background: #07101d;
      color: var(--text);
      font: inherit;
      outline: none;
    }}
    input:focus {{ border-color: var(--accent-2); box-shadow: 0 0 0 3px rgba(95, 160, 255, 0.15); }}
    button {{
      margin-top: 4px;
      padding: 12px 16px;
      border: 0;
      border-radius: 999px;
      background: linear-gradient(180deg, #f2bd78, #d29345);
      color: #08111f;
      font-weight: 700;
      cursor: pointer;
    }}
    .meta {{ margin-top: 16px; font-size: 13px; color: var(--muted); }}
    .meta code {{ color: var(--text); }}
  </style>
</head>
<body>
  <main>
    <p class="meta">Community intel</p>
    <h1>Sign in with your WON account</h1>
    <p>Authenticate once to connect or link your Homeworld Stats profile, then come straight back to your stats page.</p>
    {error_html}
    <form method="post" action="/web-auth/login?{form_query}">
      <label>Username
        <input name="username" autocomplete="username" spellcheck="false" required>
      </label>
      <label>Password
        <input type="password" name="password" autocomplete="current-password" required>
      </label>
      <button type="submit">Continue</button>
    </form>
    <p class="meta">Return target: <code>{escape(str(return_to or ""))}</code></p>
  </main>
</body>
</html>"""
        return html.encode("utf-8")

    def exchange_code(
        self,
        code: str,
        product: str,
        shared_secret: str,
    ) -> dict[str, Any]:
        if shared_secret != self.shared_secret:
            raise ValueError("invalid_shared_secret")

        with self._lock:
            record = self._codes.pop(str(code), None)

        if record is None:
            raise ValueError("invalid_or_consumed_code")
        if time.time() > record.expires_at:
            raise ValueError("expired_code")
        if record.product != self._resolve_product(product):
            raise ValueError("product_mismatch")

        return {
            "product": record.product,
            "username": record.username,
            "return_to": record.return_to,
            "issued_at": record.issued_at,
            "expires_at": record.expires_at,
        }


WebAuthBridge = GatewayWebAuthBridge
