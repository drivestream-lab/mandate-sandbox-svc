"""verify-runner-live: PR code in the sandbox must not reach the lab's services.

Tries each lab service directly (by its lab_local address and through Docker
Desktop's host address, where the lab publishes its ports), then from the sandbox
engine's own network (docker run --network host), then through the egress proxy.
Only the proxy's way to the public internet may work.
"""

import os
import socket
import subprocess
import warnings
from urllib.parse import urlsplit

TARGETS = [('lab-postgres@lab_local', '172.18.0.3', 5432), ('lab-redis@lab_local', '172.18.0.2', 6379), ('lab-litellm@lab_local', '172.18.0.4', 8000), ('lab-paperclip@lab_local', '172.18.0.5', 3100), ('postgres@host', '192.168.65.254', 5432), ('redis@host', '192.168.65.254', 6379), ('litellm@host', '192.168.65.254', 4000), ('paperclip@host', '192.168.65.254', 3100), ('postgres@host.docker.internal', 'host.docker.internal', 5432)]


def reach(host: str, port: int) -> bool:
    try:
        socket.create_connection((host, port), timeout=3).close()
        return True
    except OSError:
        return False


def proxy_connect(host: str, port: int) -> str:
    proxy = urlsplit(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or "")
    if not proxy.hostname:
        return "no proxy configured"
    with socket.create_connection((proxy.hostname, proxy.port or 3128), timeout=10) as s:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        return s.recv(200).split(b"\r\n", 1)[0].decode(errors="replace")


def hostnet_reached() -> list[str]:
    script = "; ".join(
        f"nc -z -w3 {h} {p} && echo REACHED {label}" for label, h, p in TARGETS if not h.startswith("host.")
    )
    res = subprocess.run(
        ["docker", "run", "--rm", "--network", "host", "busybox:1.37", "sh", "-c", script + "; true"],
        capture_output=True, text=True, timeout=600,
    )
    if res.returncode != 0:
        raise AssertionError(f"could not probe from the engine's network: {res.stderr.strip()[:200]}")
    warnings.warn("ISOLATION_PROBE_HOSTNET: searched")
    return [line.split(" ", 1)[1] for line in res.stdout.splitlines() if line.startswith("REACHED ")]


def test_sandbox_cannot_reach_the_lab() -> None:
    reached = []
    for label, host, port in TARGETS:
        ok = reach(host, port)
        warnings.warn(f"ISOLATION_PROBE {label} {host}:{port} {'REACHABLE' if ok else 'blocked'}")
        if ok:
            reached.append(label)
    reached += [f"hostnet:{label}" for label in hostnet_reached()]
    via_proxy = proxy_connect("192.168.65.254", 443)
    warnings.warn(f"ISOLATION_PROBE_PROXY_LAB: {via_proxy}")
    if " 200 " in f"{via_proxy} ":
        reached.append("proxy:192.168.65.254:443")
    public = proxy_connect("pypi.org", 443)
    warnings.warn(f"ISOLATION_PROBE_PROXY_PUBLIC: {public}")
    assert " 200 " in f"{public} ", "the proxy should still reach the public internet"
    warnings.warn(f"ISOLATION_PROBE_RESULT: {'REACHED ' + str(reached) if reached else 'blocked'}")
    assert not reached
