"""Check the actual HAProxy collection path expression without a dependency."""
from pathlib import Path
import re
import unittest

class IngressTests(unittest.TestCase):
    def test_only_exact_collections_and_item_subpaths(self):
        config = Path(__file__).resolve().parents[1] / 'deploy/haproxy.cfg'
        acl = next(line.split() for line in config.read_text().splitlines() if line.strip().startswith('acl main_api '))
        self.assertEqual(acl[2], 'path_reg')
        self.assertEqual(len(acl), 4)
        pattern = re.compile(acl[3])
        for path in ['/api/records/v1/main_ops','/api/records/v1/aux_ops','/api/records/v1/main_ops/12']:
            self.assertIsNotNone(pattern.search(path))
        for path in ['/api/records/v1/main_ops_admin','/api/records/v1/aux_ops2','/prefix/api/records/v1/main_ops','/api/admin']:
            self.assertIsNone(pattern.search(path))

if __name__ == '__main__': unittest.main()
