import unittest
from unittest import mock

from s3 import S3Client, classify_status, quote_etag, Reconciliation


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

    def test_unknown_put_reconciles_by_head_then_get(self):
        c = S3Client("b", "r", "a", "s", "https://s3.example")
        with mock.patch.object(c, "head", side_effect=OSError("lost")), mock.patch.object(c, "get", return_value=(200, {"ETag": '"x"'}, b"data")):
            self.assertEqual(c.reconcile_put("k", b"data", '"x"'), Reconciliation.COMMITTED)
        with mock.patch.object(c, "head", return_value=(404, {}, b"")):
            self.assertEqual(c.reconcile_put("k", b"data", '"x"'), Reconciliation.DISCARDED)


if __name__ == "__main__":
    unittest.main()
