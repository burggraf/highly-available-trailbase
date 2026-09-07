"""Small stdlib S3-compatible client; credentials stay in memory and are never logged."""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen
from http.client import HTTPSConnection

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


def header_value(headers: dict[str, str], name: str) -> str:
    return next((value for key, value in headers.items() if key.lower() == name.lower()), "")


class Reconciliation(Enum):
    COMMITTED = "committed"
    DISCARDED = "discarded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SignedRequest:
    url: str
    headers: dict[str, str]


@dataclass(frozen=True)
class ReconciliationProbe:
    method: str
    status: int | None
    etag: str
    payload_sha256: str
    request_id: str

    @classmethod
    def from_response(cls, method: str, response: tuple[int, dict[str, str], bytes]):
        status, headers, body = response
        return cls(method, status, header_value(headers, "etag"), hashlib.sha256(body).hexdigest(), header_value(headers, "x-amz-request-id") or header_value(headers, "x-request-id"))


@dataclass(frozen=True)
class ReconciliationResult:
    outcome: Reconciliation
    probes: tuple[ReconciliationProbe, ...]


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
        canonical_query = "&".join(f"{quote(str(k), safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted((query or {}).items()))
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
        path = ("/" + quote(self.bucket, safe="-_.~") + "/" + quote(key, safe="/-_.~")) if key else ("/" + quote(self.bucket, safe="-_.~"))
        signed = self.signed_request(method, path, headers or {}, body, query=query)
        url = signed.url + (("?" + "&".join(f"{quote(str(k), safe='-_.~')}={quote(str(v), safe='-_.~')}" for k, v in sorted((query or {}).items()))) if query else "")
        try:
            with urlopen(Request(url, data=body if method not in {"GET", "HEAD"} else None, headers=signed.headers, method=method), timeout=30) as response:
                return response.status, dict(response.headers.items()), response.read()
        except HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()
        except (URLError, TimeoutError):
            raise

    def put(self, key: str, body: bytes, *, etag: str | None = None, if_none_match: bool = False, headers: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        if etag is not None and if_none_match: raise ValueError("conflicting conditions")
        conditional = {"If-Match": quote_etag(etag)} if etag is not None else ({"If-None-Match": "*"} if if_none_match else {})
        conditional.update(headers or {})
        return self.request("PUT", key, body=body, headers=conditional)

    def put_discarded(self, key: str, body: bytes, *, etag: str | None = None, if_none_match: bool = False) -> Reconciliation:
        """Send the complete TLS request, then close before reading its status."""
        if etag is not None and if_none_match:
            raise ValueError("conflicting conditions")
        headers = {"If-Match": quote_etag(etag)} if etag is not None else ({"If-None-Match": "*"} if if_none_match else {})
        path = "/" + quote(self.bucket, safe="-_.~") + "/" + quote(key, safe="/-_.~")
        signed = self.signed_request("PUT", path, headers, body)
        parts = urlsplit(signed.url)
        connection = HTTPSConnection(parts.hostname, parts.port or 443, timeout=30)
        try:
            connection.request("PUT", parts.path, body=body, headers=signed.headers)
        finally:
            connection.close()
        return Reconciliation.UNKNOWN

    def get(self, key: str): return self.request("GET", key)
    def head(self, key: str): return self.request("HEAD", key)
    def list(self, prefix: str = ""): return self.request("GET", query={"list-type": "2", "prefix": prefix})
    def delete(self, key: str, *, etag: str | None = None):
        return self.request("DELETE", key, headers={"If-Match": quote_etag(etag)} if etag is not None else {})

    def reconcile_put_detailed(self, key: str, body: bytes, etag: str) -> ReconciliationResult:
        probes: list[ReconciliationProbe] = []
        # ponytail: three authoritative rounds bound degraded-provider runtime.
        for _ in range(3):
            absent: set[str] = set()
            for method, read in (("HEAD", self.head), ("GET", self.get)):
                try:
                    response = read(key)
                except (OSError, URLError):
                    probes.append(ReconciliationProbe(method, None, "", hashlib.sha256(b"").hexdigest(), ""))
                    continue
                probe = ReconciliationProbe.from_response(method, response)
                probes.append(probe)
                status, headers, got = response
                if status == 404:
                    absent.add(method)
                if method == "GET" and status == 200 and got == body and probe.etag == quote_etag(etag):
                    return ReconciliationResult(Reconciliation.COMMITTED, tuple(probes))
            if absent == {"HEAD", "GET"}:
                return ReconciliationResult(Reconciliation.DISCARDED, tuple(probes))
        return ReconciliationResult(Reconciliation.UNKNOWN, tuple(probes))

    def reconcile_put(self, key: str, body: bytes, etag: str) -> Reconciliation:
        return self.reconcile_put_detailed(key, body, etag).outcome


def _read_s3_values(path: Path, repository: Path | None = None) -> dict[str, str]:
    if require_private_file is None: raise RuntimeError("secure env loader unavailable")
    require_private_file(path, repository)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"export ([A-Z][A-Z0-9_]*)=(?:'([^'\n]*)'|\"([^\"\n]*)\"|([^\s]+))", line)
        if not match: raise ValueError("invalid S3 env")
        aliases = {"AWS_ACCESS_KEY_ID": "IDRIVE_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY": "IDRIVE_SECRET_KEY", "AWS_REGION": "IDRIVE_REGION", "HAT_S3_ENDPOINT": "IDRIVE_ENDPOINT", "HAT_S3_BUCKET": "IDRIVE_BUCKET"}
        key = aliases.get(match.group(1), match.group(1))
        if key not in {"IDRIVE_ENDPOINT", "IDRIVE_BUCKET", "IDRIVE_REGION", "IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"} or key in values: raise ValueError("invalid S3 env")
        value = next(group for group in match.groups()[1:] if group is not None)
        if not value: raise ValueError("invalid S3 env")
        values[key] = value
    required = {"IDRIVE_ENDPOINT", "IDRIVE_BUCKET", "IDRIVE_REGION", "IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"}
    if set(values) != required: raise ValueError("invalid S3 env")
    register_secret(values["IDRIVE_ACCESS_KEY"]); register_secret(values["IDRIVE_SECRET_KEY"])
    return values

def load_s3_env(path: Path, repository: Path | None = None) -> dict[str, str]:
    return {k: v for k, v in _read_s3_values(path, repository).items() if k not in {"IDRIVE_ACCESS_KEY", "IDRIVE_SECRET_KEY"}}

def client_from_env(path: Path, repository: Path | None = None) -> S3Client:
    values = _read_s3_values(path, repository)
    return S3Client(values["IDRIVE_BUCKET"], values["IDRIVE_REGION"], values["IDRIVE_ACCESS_KEY"], values["IDRIVE_SECRET_KEY"], values["IDRIVE_ENDPOINT"])
