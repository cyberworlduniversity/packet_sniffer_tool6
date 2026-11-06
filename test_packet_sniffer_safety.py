import contextlib
import io
import socket
import struct
import unittest

import packet_sniffer


class PacketParserSafetyTests(unittest.TestCase):
    def test_ethernet_parser_returns_network_order_ethertype(self):
        frame = struct.pack("!6s6sH", b"123456", b"abcdef", 0x0800) + b"payload"
        _, _, ethertype, payload = packet_sniffer.parse_ethernet(frame)
        self.assertEqual(ethertype, 0x0800)
        self.assertEqual(payload, b"payload")

    def test_ipv4_parser_rejects_truncated_and_invalid_headers(self):
        with self.assertRaises(ValueError):
            packet_sniffer.parse_ipv4(b"short")
        invalid = bytearray(20)
        invalid[0] = 0x35
        with self.assertRaises(ValueError):
            packet_sniffer.parse_ipv4(bytes(invalid))

    def test_tcp_and_udp_parsers_reject_truncated_headers(self):
        with self.assertRaises(ValueError):
            packet_sniffer.parse_tcp(b"short")
        with self.assertRaises(ValueError):
            packet_sniffer.parse_udp(b"short")

    def test_tcp_payload_is_hidden_by_default(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            packet_sniffer.display_tcp(1234, 80, 1, 1, "ACK", b"private-token")
        self.assertNotIn("private-token", output.getvalue())

    def test_tcp_payload_requires_explicit_opt_in(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            packet_sniffer.display_tcp(1234, 80, 1, 1, "ACK", b"private-token", show_payload=True)
        self.assertIn("private-token", output.getvalue())

    def test_negative_packet_limit_is_rejected_before_socket_creation(self):
        with self.assertRaises(ValueError):
            packet_sniffer.sniff(packet_limit=-1)


if __name__ == "__main__":
    unittest.main()
