"""verify-runner-live: the job must see no build key and no GitHub token.

Prints the environment and lists /run/secrets, ~/.mandate, /secrets and /certs, then
searches them, and the sandbox engine's own filesystem, for keys and tokens.
"""

import os
import re
import shutil
import subprocess
import warnings
from pathlib import Path

TOKEN = re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}")
TOKEN_ENV = {"GITHUB_TOKEN", "GH_TOKEN", "GITHUB_APP_PRIVATE_KEY", "MANDATE_RUNNER_SECRETS_DIR"}
PLACES = [Path("/run/secrets"), Path.home() / ".mandate", Path("/secrets"), Path("/certs")]


def listing() -> list[str]:
    found: list[str] = []
    for place in PLACES:
        if place.exists():
            found.append(str(place))
            found.extend(str(p) for p in sorted(place.rglob("*")))
    return found


def secret_in(text: str) -> bool:
    return "PRIVATE KEY" in text or TOKEN.search(text) is not None


def leaks() -> list[str]:
    found: list[str] = []
    for name, value in os.environ.items():
        if name in TOKEN_ENV or secret_in(value):
            found.append(f"env:{name}")
    for item in listing():
        path = Path(item)
        if path.is_file():
            try:
                text = path.read_text(errors="ignore")
            except OSError:
                continue
            if secret_in(text) or path.name == "private-key.pem":
                found.append(f"file:{item}")
    return found


def engine_leaks() -> list[str]:
    """Through the sandbox's Docker engine: any App key on the engine's own filesystem."""
    if shutil.which("docker") is None:
        warnings.warn("SECRETS_PROBE_ENGINE: no docker CLI, engine not searched")
        return []
    script = (
        "find /host -xdev \\( -path /host/proc -o -path /host/sys -o -path /host/var/lib/docker \\) "
        "-prune -o \\( -name private-key.pem -o -path '*/.mandate/*' \\) -print 2>/dev/null"
    )
    res = subprocess.run(
        ["docker", "run", "--rm", "-v", "/:/host:ro", "busybox:1.37", "sh", "-c", script],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if res.returncode != 0:
        warnings.warn(f"SECRETS_PROBE_ENGINE: not searched ({res.stderr.strip()[:120]})")
        return []
    warnings.warn("SECRETS_PROBE_ENGINE: searched the sandbox engine's filesystem")
    return [f"engine:{line}" for line in res.stdout.split() if line]


def shown(value: str) -> str:
    return "<token-like value>" if secret_in(value) else value


def test_job_sees_no_build_key_or_token() -> None:
    env = {name: shown(value) for name, value in sorted(os.environ.items())}
    places = listing()
    found = leaks() + engine_leaks()
    warnings.warn(f"SECRETS_PROBE_ENV: {env}")
    warnings.warn(f"SECRETS_PROBE_LISTING: {places or 'nothing under ' + str(PLACES)}")
    if found:
        warnings.warn(f"SECRETS_PROBE_RESULT: FOUND {found}")
    else:
        warnings.warn("SECRETS_PROBE_RESULT: clean")
    assert not found
