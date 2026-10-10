import os
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import a9_discover as D
import a9_proto as P
import extract_a9_snapshot as X


def frame(kind, body):
    return bytes([kind << 4]) + P.enc_varint(len(body)) + body


def packet(seq, payload=b'', flags=16):
    tcp = struct.pack('>HHII', 12345, P.PORT, seq, 0) + bytes([0x50, flags]) + b'\0' * 6 + payload
    ip = bytes([0x45, 0]) + struct.pack('>H', 20 + len(tcp)) + b'\0' * 4 + bytes([64, 6]) + b'\0\0'
    return ip + socket.inet_aton('192.0.2.1') + socket.inet_aton('192.0.2.2') + tcp


class RegressionTests(unittest.TestCase):
    def test_credentials_do_not_mix_cameras(self):
        cfg = {'did': 'A', 'secret': 'secret-A', 'ip': '192.0.2.1'}
        dev = {'did': 'B', 'secret': 'secret-B', 'ip': '192.0.2.2'}
        with patch.object(D, 'load_config', return_value=cfg), patch.object(D, 'discover', return_value=[dev]):
            self.assertEqual(D.resolve_credentials(did='B'), ('192.0.2.2', b'B', b'secret-B'))
            with self.assertRaises(SystemExit):
                D.resolve_credentials(ip='192.0.2.3', did='B')

    def test_strict_selection(self):
        with self.assertRaises(SystemExit): D.select_one([{'did': 'A'}], 'B')
        with self.assertRaises(SystemExit): D.select_one([{'did': 'A'}, {'did': 'B'}])

    def test_private_atomic_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'camera.json'
            old_temp = Path(str(path) + '.tmp.' + str(os.getpid()))
            old_temp.write_text('leave me alone')
            old_temp.chmod(0o644)
            D.save_config(str(path), {'did': 'synthetic', 'secret': 'synthetic'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(old_temp.read_text(), 'leave me alone')
            with patch.object(D.os, 'replace', side_effect=OSError('synthetic failure')):
                with self.assertRaises(SystemExit): D.save_config(str(path), {})
            self.assertFalse(list(Path(directory).glob('.a9-config-*')))

    def test_reassembly_overlap_wrap_and_gaps(self):
        self.assertEqual(P.reassemble_tcp([(100, b'abc'), (102, b'cdef'), (100, b'abc')]), b'abcdef')
        self.assertEqual(P.reassemble_tcp([(0xfffffffe, b'ab'), (0, b'cd')]), b'abcd')
        with self.assertRaisesRegex(ValueError, 'missing'): P.reassemble_tcp([(100, b'a'), (110, b'b')])
        with self.assertRaisesRegex(ValueError, 'limit'): P.reassemble_tcp([(0, b'a'), (1 << 30, b'b')])
        with self.assertRaisesRegex(ValueError, 'conflicting'): P.reassemble_tcp([(1, b'ab'), (2, b'x')])

    def test_reused_tcp_tuple_is_separated(self):
        packets = [packet(100, flags=2), packet(101, b'abc'), packet(104, flags=4),
                   packet(500, flags=2), packet(501, b'xyz')]
        data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
        for pkt in packets: data += struct.pack('<IIII', 0, 0, len(pkt), len(pkt)) + pkt
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'synthetic.pcap'
            path.write_bytes(data)
            self.assertEqual(list(P.read_pcap_streams(path).values()), [b'abc', b'xyz'])
            path.write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError, 'truncated'): P.read_pcap_streams(path)

    def test_media_byte_limit(self):
        with patch.object(P, 'MAX_JPEG_BYTES', 8):
            frags = P.MediaFragments()
            frags.append(b'12345')
            with self.assertRaises(ValueError): frags.append(b'6789')
            self.assertEqual(frags.byte_count, 0)
            self.assertEqual(frags, [])

    def test_extraction_selects_auth_flow(self):
        key = b'0' * 32
        auth_flow = ('192.0.2.1', P.PORT, '192.0.2.2', 12345, 1)
        other_flow = ('192.0.2.3', P.PORT, '192.0.2.2', 12346, 2)
        with patch.object(P, '_PREKEY', b'synthetic-prekey'):
            unrelated = P.build_ctrl(1, P.CMD_STATUS, P.pb_field_bytes(1, b'1' * 32), flag=0x0d)
            auth = P.build_ctrl(2, P.CMD_LANAUTH, P.pb_field_bytes(1, key), flag=0x0d)
            media = b'\x80\x00' + b'\x00' * 7 + b'\xff\xd8correct\xff\xd9'
            other_media = media.replace(b'correct', b'wrong')
            streams = {other_flow: unrelated + frame(6, other_media), auth_flow: auth + frame(6, media)}
            self.assertEqual(X.recover_session_key(streams), key)
            self.assertEqual(X.extract_first_jpeg(streams, key), b'\xff\xd8correct\xff\xd9')
            streams[other_flow] = auth + frame(6, other_media)
            with self.assertRaises(SystemExit): X.recover_session_key(streams)


if __name__ == '__main__':
    unittest.main()
