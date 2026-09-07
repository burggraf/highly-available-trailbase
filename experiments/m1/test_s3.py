import tempfile
import unittest
from pathlib import Path
from unittest import mock

from s3 import S3Client, classify_status, load_s3_env, quote_etag, Reconciliation


class SigV4Tests(unittest.TestCase):
    def test_published_aws_get_vector(self):
        # AWS S3 worked example credentials/date and GET request.
        c = S3Client("examplebucket", "us-east-1", "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "https://examplebucket.s3.amazonaws.com")
        signed = c.signed_request("GET", "/test.txt", {"Range": "bytes=0-9"}, b"", timestamp="20130524T000000Z")
        self.assertEqual(signed.headers["Authorization"], "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_status_and_quoted_etag(self):
        self.assertEqual(quote_etag('abc'), '"abc"')
        self.assertEqual(quote_etag('"abc"'), '"abc"')
        self.assertEqual(classify_status(200), "ok")
        self.assertEqual(classify_status(409), "conflict")
        self.assertEqual(classify_status(412), "precondition")
        self.assertEqual(classify_status(599), "unknown")

    def test_empty_etag_stays_conditional(self):
        c = S3Client("b", "r", "a", "s", "https://s3.example")
        with mock.patch.object(c, "request", return_value=(412, {}, b"")) as request:
            c.put("k", b"x", etag="")
            c.delete("k", etag="")
        self.assertEqual(request.call_args_list[0].kwargs["headers"], {"If-Match": '""'})
        self.assertEqual(request.call_args_list[1].kwargs["headers"], {"If-Match": '""'})

    def test_unknown_put_reconciles_by_authoritative_get(self):
        c = S3Client("b", "r", "a", "s", "https://s3.example")
        with mock.patch.object(c, "head", return_value=(200, {"ETag": '"x"'}, b"")), mock.patch.object(c, "get", return_value=(200, {"ETag": '"x"'}, b"data")):
            result = c.reconcile_put_detailed("k", b"data", '"x"')
        self.assertEqual(result.outcome, Reconciliation.COMMITTED)
        self.assertEqual([(probe.method, probe.status) for probe in result.probes], [("HEAD", 200), ("GET", 200)])
        with mock.patch.object(c, "head", return_value=(404, {"X-Amz-Request-Id": "r"}, b"")), mock.patch.object(c, "get", return_value=(404, {"X-Amz-Request-Id": "g"}, b"")):
            result = c.reconcile_put_detailed("k", b"data", '"x"')
        self.assertEqual(result.outcome, Reconciliation.DISCARDED)
        self.assertEqual([(probe.method, probe.status, probe.request_id) for probe in result.probes], [("HEAD", 404, "r"), ("GET", 404, "g")])

    def test_reconcile_requires_exact_etag_and_bytes(self):
        c = S3Client("b", "r", "a", "s", "https://s3.example")
        with mock.patch.object(c, "head", return_value=(200, {"ETag": '"wrong"'}, b"")), mock.patch.object(c, "get", return_value=(200, {"ETag": '"x"'}, b"wrong")):
            self.assertEqual(c.reconcile_put("k", b"data", '"x"'), Reconciliation.UNKNOWN)

    def test_s3_env_accepts_standard_shell_value_forms(self):
        lines = (
            "export AWS_ACCESS_KEY_ID=identifier\n"
            "export AWS_SECRET_ACCESS_KEY='secret/value'\n"
            "export AWS_REGION=\"us-west-2\"\n"
            "export HAT_S3_ENDPOINT=https://endpoint.example\n"
            "export HAT_S3_BUCKET='bucket'\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "env"; path.write_text(lines)
            with mock.patch("s3.require_private_file"):
                self.assertEqual(load_s3_env(path), {"IDRIVE_REGION": "us-west-2", "IDRIVE_ENDPOINT": "https://endpoint.example", "IDRIVE_BUCKET": "bucket"})

    def test_discarded_put_closes_without_reading_response(self):
        c = S3Client("b", "r", "a", "s", "https://s3.example")
        with mock.patch("s3.HTTPSConnection") as connection:
            conn = connection.return_value
            self.assertEqual(c.put_discarded("k", b"data"), Reconciliation.UNKNOWN)
            conn.request.assert_called_once()
            conn.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
