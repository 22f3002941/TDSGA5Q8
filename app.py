from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from urllib.parse import urlparse
from pathlib import Path
import socket
import ipaddress
import requests

app = FastAPI()

SANDBOX_ROOT = Path("/srv/agent-redteam/sandbox-34cc8b381b").resolve()
ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}


def normalize_candidate(user_path: str) -> Path:
    p = Path(user_path)
    if p.is_absolute():
        return p.resolve()
    return (SANDBOX_ROOT / p).resolve()


def is_within_sandbox(user_path: str):
    try:
        candidate = normalize_candidate(user_path)
        candidate.relative_to(SANDBOX_ROOT)
        return True, str(candidate)
    except Exception:
        return False, None


def read_file_tool(path: str):
    ok, final_path = is_within_sandbox(path)
    if not ok:
        return {"action": "block", "reason": "path escapes sandbox", "result": None}

    p = Path(final_path)
    if not p.exists() or not p.is_file():
        return {"action": "block", "reason": "file missing", "result": None}

    try:
        content = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return {"action": "block", "reason": "read failed", "result": None}

    return {"action": "allow", "reason": "safe sandbox file", "result": {"content": content}}


def host_is_exactly_allowed(hostname: str) -> bool:
    return hostname in ALLOWED_HOSTS


def host_resolves_to_safe_ip(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return False

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

    return True


def url_is_safe(raw_url: str):
    try:
        parsed = urlparse(raw_url)
    except Exception:
        return False, "bad url"

    if parsed.scheme not in ALLOWED_SCHEMES:
        return False, "bad scheme"

    if not parsed.hostname:
        return False, "missing host"

    if parsed.username or parsed.password:
        return False, "userinfo not allowed"

    if not host_is_exactly_allowed(parsed.hostname):
        return False, "host not allowlisted"

    if not host_resolves_to_safe_ip(parsed.hostname):
        return False, "unsafe ip"

    return True, "safe url"


def fetch_url_tool(url: str):
    ok, reason = url_is_safe(url)
    if not ok:
        return {"action": "block", "reason": reason, "result": None}

    try:
        resp = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            headers={"User-Agent": "guardrail/1.0"},
        )
    except Exception:
        return {"action": "block", "reason": "request failed", "result": None}

    if 300 <= resp.status_code < 400:
        location = resp.headers.get("Location")
        if not location:
            return {"action": "block", "reason": "redirect without location", "result": None}

        if location.startswith("/"):
            parsed = urlparse(url)
            location = f"{parsed.scheme}://{parsed.hostname}{location}"

        ok2, reason2 = url_is_safe(location)
        if not ok2:
            return {"action": "block", "reason": "redirect blocked", "result": None}

        try:
            resp = requests.get(
                location,
                timeout=10,
                allow_redirects=False,
                headers={"User-Agent": "guardrail/1.0"},
            )
        except Exception:
            return {"action": "block", "reason": "redirect request failed", "result": None}

    return {"action": "allow", "reason": "safe allowlisted url", "result": {"text": resp.text}}


@app.post("/")
async def guardrail(request: Request):
    payload = await request.json()
    tool = payload.get("tool", "")
    arguments = payload.get("arguments", {})

    if tool == "read_file":
        return JSONResponse(read_file_tool(arguments.get("path", "")))

    if tool == "fetch_url":
        return JSONResponse(fetch_url_tool(arguments.get("url", "")))

    return JSONResponse({"action": "block", "reason": "unknown tool", "result": None})