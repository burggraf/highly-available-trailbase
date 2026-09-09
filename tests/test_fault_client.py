import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / 'hat'))
import client


class FaultClientTests(unittest.TestCase):
    def test_local_ack_and_closed_ledger(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length','0')))
                self.send_response(201); self.end_headers(); self.wfile.write(b'{"ids":[7]}')
            def log_message(self, *_): pass
        server=HTTPServer(('127.0.0.1',0),Handler); thread=threading.Thread(target=server.serve_forever); thread.start()
        try:
            with tempfile.TemporaryDirectory() as d:
                root=Path(d).resolve(); token=root/'tokens'; token.write_text(json.dumps({'auth_token':'secret'})); token.chmod(0o600)
                private=root/'private'; private.mkdir(mode=0o700)
                out=private/'run.jsonl'; client.produce(token,out,'d1-source',duration=.1,interval=.1,base='http://127.0.0.1:%s'%server.server_port)
                events=client.read_closed_ledger(out,expected_epoch='d1-source')
                self.assertEqual(events[0]['event'],'submitted'); self.assertEqual(events[1]['event'],'acknowledged')
                self.assertEqual(out.stat().st_mode & 0o777,0o600)
        finally: server.shutdown(); thread.join(); server.server_close()

    def test_incomplete_or_extra_data_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d).resolve()/'x'; p.write_text('{"event":"start"}\n'); p.chmod(0o600)
            with self.assertRaises(ValueError): client.read_closed_ledger(p,expected_epoch='d1-source')

if __name__ == '__main__': unittest.main()
