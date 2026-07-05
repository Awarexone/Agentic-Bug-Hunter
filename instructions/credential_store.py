"""
Secure credential store — loads auth credentials from .env files.

Credentials are loaded from a .gitignored .env file and never written to
hunt-memory, conversation transcripts, or any persistent storage.

Usage:
    store = CredentialStore(Path(".env"))
    cookie = store.get("TARGET_COOKIE")
    headers = store.as_headers("TARGET_TOKEN", header_type="bearer")
"""

from pathlib import Path


class CredentialStore:
    """Load and manage credentials from .env files without leaking values."""

    def __init__(self, env_path: str | Path):
        self._data: dict[str, str] = {}
        self._path = Path(env_path)
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        """Parse .env file into key-value pairs."""
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                # Strip surrounding quotes
                if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                    value = value[1:-1]
                self._data[key] = value

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get a credential value by key."""
        return self._data.get(key, default)

    def has(self, key: str) -> bool:
        """Check if a key exists without exposing the value."""
        return key in self._data

    def keys(self) -> list[str]:
        """Return all credential key names (not values)."""
        return list(self._data.keys())

    def get_masked(self, key: str) -> str | None:
        """Return a masked version of the value (first 3 chars + ***)."""
        value = self._data.get(key)
        if value is None:
            return None
        if len(value) <= 3:
            return "***"
        return value[:3] + "***"

    def as_headers(self, key: str, header_type: str = "bearer") -> dict[str, str]:
        """Build an HTTP header dict from a stored credential.

        Args:
            key: The credential key to use.
            header_type: One of 'bearer', 'cookie', 'api_key'.

        Returns:
            Dict with the appropriate header, or empty dict if key not found.
        """
        value = self._data.get(key)
        if value is None:
            return {}

        if header_type == "bearer":
            return {"Authorization": f"Bearer {value}"}
        elif header_type == "cookie":
            return {"Cookie": value}
        elif header_type == "api_key":
            return {"X-API-Key": value}
        return {}

    def __repr__(self) -> str:
        keys_str = ", ".join(self._data.keys())
        return f"CredentialStore(keys=[{keys_str}])"

    def __str__(self) -> str:
        masked = {k: self.get_masked(k) for k in self._data}
        pairs = ", ".join(f"{k}={v}" for k, v in masked.items())
        return f"CredentialStore({pairs})"
