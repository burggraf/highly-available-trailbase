"""Small stdlib S3-compatible client; credentials stay in memory and are never logged."""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

try:
    from run import require_private_file, register_secret
except ImportError:  # pragma: no cover
    require_private_file = None
    register_secret = lambda value: None


def quote_etag(value: str) -> str:
    value = value.strip()
    return value if value.startswith('"') and value.endswith('"') else f'"{value.strip(chr(34))}"'


def classify_status(status: int | None) -> str:
    return {200: "ok", 201: "ok", 204: "ok", 409: "conflict", 412: "precondition"}.get(status, "unknown")


def classify_precondition(status: int | None) -> str:
    return {200: "applied", 201: "applied", 204: "applied", 409: "conflict", 412: "refused"}.get(status, "unknown")


class Reconciliation(Enum):
    COMMITTED = "committed"
    DISCARDED = "discarded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SignedRequest:
    url: str
    headers: dict[str, str]


def _hmac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


class S3Client:
    def __init__(self, bucket: str, region: str, access_key: str, secret_key: str, endpoint: str):
        if not re.fullmatch(r"[A-Za-z0-9.-]+", bucket) or not region or not endpoint.startswith("https://"):
            raise ValueError("invalid S3 endpoint configuration")
        self.bucket, self.region = bucket, region
        self.access_key, self.secret_key = access_key, secret_key
        self.endpoint = endpoint.rstrip("/")
        self._host = urlsplit(self.endpoint).netloc

    def signed_request(self, method: str, path: str, headers: dict[str, str], body: bytes, *, query: dict[str, str] | None = None, timestamp: str | None = None) -> SignedRequest:
        import datetime
        now = timestamp or datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        day = now[:8]
        payload_hash = hashlib.sha256(body).hexdigest()
        actual = {k.lower(): str(v).strip() for k, v in headers.items()}
        actual.setdefault("host", self._host)
        actual["x-amz-content-sha256"] = payload_hash
        actual["x-amz-date"] = now
        canonical_headers = "".join(f"{k}:{' '.join(actual[k].split())}\n" for k in sorted(actual))
        signed = ";".join(sorted(actual))
        canonical_uri = "/" + "/".join(quote(part, safe="-_.~") for part in path.lstrip("/").split("/"))
        canonical_query = urlencode(sorted((query or {}).items()), quote_via=quote)
        canonical = "\n".join((method.upper(), canonical_uri, canonical_query, canonical_headers, signed, payload_hash))
        scope = f"{day}/{self.region}/s3/aws4_request"
        string = "\n".join(("AWS4-HMAC-SHA256", now, scope, hashlib.sha256(canonical.encode()).hexdigest()))
        k_date = _hmac(("AWS4" + self.secret_key).encode(), day)
        k_region = hmac.new(k_date, self.region.encode(), hashlib.sha256).digest()
        k_service = hmac.new(k_region, b"s3", hashlib.sha256).digest()
        signing = hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()
        signature = hmac.new(signing, string.encode(), hashlib.sha256).hexdigest()
        actual["Authorization"] = f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, SignedHeaders={signed}, Signature={signature}"
        return SignedRequest(self.endpoint + canonical_uri, actual)

    def request(self, method: str, key: str = "", *, body: bytes = b"", headers: dict[str, str] | None = None, query: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        path = "/" + quote(key, safe="/-_.~") if key else "/"
        signed = self.signed_request(method, path, headers or {}, body, query=query)
        url = signed.url + ("?" + urlencode(sorted((query or {}).items())) if query else "")
        try:
            with urlopen(Request(url, data=body if method not in {"GET", "HEAD"} else None, headers=signed.headers, method=method), timeout=30) as response:
                return response.status, dict(response.headers.items()), response.read()
        except HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()
        except (URLError, TimeoutError):
            raise

    def put(self, key: str, body: bytes, *, etag: str | None = None, if_none_match: bool = False) -> tuple[int, dict[str, str], bytes]:
        if etag and if_none_match: raise ValueError("conflicting conditions")
        headers = {"If-Match": quote_etag(etag)} if etag else ({"If-None-Match": "*"} if if_none_match else {})
        return self.request("PUT", key, body=body, headers=headers)

    def get(self, key: str): return self.request("GET", key)
    def head(self, key: str): return self.request("HEAD", key)
    def list(self, prefix: str = ""): return self.request("GET", query={"list-type": "2", "prefix": prefix})
    def delete(self, key: str, *, etag: str | None = None):
        return self.request("DELETE", key, headers={"If-Match": quote_etag(etag)} if etag else {})

    def reconcile_put(self, key: str, body: bytes, etag: str) -> Reconciliation:
        try:
            status, headers, _ = self.head(key)
            if status == 404: return Reconciliation.DISCARDED
            if status in (200, 204) and headers.get("ETag", headers.get("etag", "")) == quote_etag(etag):
                return Reconciliation.COMMITTED
        except (OSError, URLError):
            pass
        try:
            status, headers, got = self.get(key)
            if status == 404: return Reconciliation.DISCARDED
            if status == 200 and got == body: return Reconciliation.COMMITTED
        except (OSError, URLError):
            pass
        return Reconciliation.UNKNOWN


def load_s3_env(path: Path, repository: Path | None = None) -> dict[str, str]:
    if require_private_file is None: raise RuntimeError("secure env loader unavailable")
    require_private_file(path, repository)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"export (IDRIVE_(?:ENDPOINT|BUCKET|REGION|ACCESS_KEY|SECRET_KEY))='([^'\n]+)'", line)
        if not match or match.group(1) in values: raise ValueError("invalid S3 env")
        values[match.group(1)] = match.group(2)
    required = {"IDRIVE_ENDPOINT", "IDRIVE_BUCKET", "IDRIVE_REGION", "IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"}
    if set(values) != required: raise ValueError("invalid S3 env")
    register_secret(values["IDRIVE_ACCESS_KEY"]); register_secret(values["IDRIVE_SECRET_KEY"])
    return {k: v for k, v in values.items() if k not in {"IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"}}


def client_from_env(path: Path, repository: Path | None = None) -> S3Client:
    if require_private_file is None: raise RuntimeError("secure env loader unavailable")
    require_private_file(path, repository)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"export (IDRIVE_(?:ENDPOINT|BUCKET|REGION|ACCESS_KEY|SECRET_KEY))='([^'\\n]+)'", line)
        if not match or match.group(1) in values: raise ValueError("invalid S3 env")
        values[match.group(1)] = match.group(2)
    if set(values) != {"IDRIVE_ENDPOINT", "IDRIVE_BUCKET", "IDRIVE_REGION", "IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"}:
        raise ValueError("invalid S3 env")
    register_secret(values["IDRIVE_ACCESS_KEY"]); register_secret(values["IDRIVE_SECRET_KEY"])
    return S3Client(values["IDRIVE_BUCKET"], values["IDRIVE_REGION"], values["IDRIVE_ACCESS_KEY"], values["IDRIVE_SECRET_KEY"], values["IDRIVE_ENDPOINT"])
