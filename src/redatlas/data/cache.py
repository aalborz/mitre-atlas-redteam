from __future__ import annotations

import os
import tempfile
from pathlib import Path

import httpx
import platformdirs

APP_NAME = "mitre-atlas-redteam"


class DataSourceError(RuntimeError):
    """Raised when a remote data source cannot be fetched."""


def get_cache_dir(override: Path | None = None) -> Path:
    if override is not None:
        cache_dir = override
    else:
        env_override = os.environ.get("REDATLAS_CACHE_DIR")
        cache_dir = (
            Path(env_override) if env_override else Path(platformdirs.user_cache_dir(APP_NAME))
        )
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def download_text(url: str, *, timeout: float = 30.0) -> str:
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise DataSourceError(f"Failed to fetch {url}: {exc}") from exc
    return response.text


def download_with_cache(url: str, cache_path: Path, *, refresh: bool = False) -> Path:
    if cache_path.exists() and not refresh:
        return cache_path

    text = download_text(url)
    cache_path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=cache_path.parent, prefix=".tmp-", suffix=cache_path.suffix)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        tmp_path.replace(cache_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    return cache_path
