"""
Comprehensive Unit Tests for Packet Parsing Engine (core/packet_parser.py).
Tests all layers, protocols, flags, fragmentation, edge cases, and dictionary conversion.
"""

import os
import sys
import unittest
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment, ICMPv6EchoRequest
from scapy.packet import Raw

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.packet_parser import (
    ParsedPacket,
    parse_packet,
    extract_tcp_flags,
    identify_app_protocol,
    PORT_PROTOCOL_MAP
)


class TestPacketParser(unittest.TestCase):
    """Test suite covering all aspects of the Packet Parsing engine."""

    def test_ethernet_ipv4_tcp_parsing(self):
        """Test extraction of Ethernet, IPv4, and TCP header fields."""
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") /
            IP(src="192.168.1.100", dst="10.0.0.1", ttl=64, proto=6) /
            TCP(sport=54321, dport=443, seq=1000, ack=2000, window=65535, flags="SA")
        )

        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertIsInstance(parsed, ParsedPacket)

        # Layer 2
        self.assertEqual(parsed.src_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.dst_mac, "aa:bb:cc:dd:ee:ff")

        # Layer 3
        self.assertEqual(parsed.ip_version, 4)
        self.assertEqual(parsed.src_ip, "192.168.1.100")
        self.assertEqual(parsed.dst_ip, "10.0.0.1")
        self.assertEqual(parsed.ttl, 64)
        self.assertEqual(parsed.ip_proto, 6)
        self.assertFalse(parsed.is_fragment)

        # Layer 4
        self.assertEqual(parsed.transport_proto, "TCP")
        self.assertEqual(parsed.src_port, 54321)
        self.assertEqual(parsed.dst_port, 443)
        self.assertEqual(parsed.tcp_seq, 1000)
        self.assertEqual(parsed.tcp_ack, 2000)
        self.assertEqual(parsed.tcp_window, 65535)
        self.assertEqual(parsed.tcp_flags, ["SYN", "ACK"])
        self.assertEqual(parsed.tcp_flags_hex, 0x12)

        # Layer 7
        self.assertEqual(parsed.app_proto, "HTTPS")

    def test_tcp_flags_individual_and_combinations(self):
        """Test extraction of every individual TCP flag and stealth combinations."""
        # 1. Individual flags
        flag_tests = [
            ("F", ["FIN"], 0x01),
            ("S", ["SYN"], 0x02),
            ("R", ["RST"], 0x04),
            ("P", ["PSH"], 0x08),
            ("A", ["ACK"], 0x10),
            ("U", ["URG"], 0x20),
            ("E", ["ECE"], 0x40),
            ("C", ["CWR"], 0x80),
        ]
        for scapy_flag, expected_list, expected_hex in flag_tests:
            pkt = Ether() / IP() / TCP(flags=scapy_flag)
            parsed = parse_packet(pkt)
            self.assertEqual(parsed.tcp_flags, expected_list, f"Failed for flag {scapy_flag}")
            self.assertEqual(parsed.tcp_flags_hex, expected_hex)

        # 2. Xmas Scan (FIN + PSH + URG)
        xmas_pkt = Ether() / IP() / TCP(flags="FPU")
        parsed_xmas = parse_packet(xmas_pkt)
        self.assertEqual(parsed_xmas.tcp_flags, ["FIN", "PSH", "URG"])
        self.assertEqual(parsed_xmas.tcp_flags_hex, 0x29)

        # 3. NULL Scan (No flags set)
        null_pkt = Ether() / IP() / TCP(flags=0)
        parsed_null = parse_packet(null_pkt)
        self.assertEqual(parsed_null.tcp_flags, [])
        self.assertEqual(parsed_null.tcp_flags_hex, 0)

        # 4. SYN+FIN Illegal Flag Combination
        syn_fin_pkt = Ether() / IP() / TCP(flags=0x03)
        parsed_syn_fin = parse_packet(syn_fin_pkt)
        self.assertEqual(parsed_syn_fin.tcp_flags, ["FIN", "SYN"])

        # 5. NS (Nonce Sum) Flag (RFC 3540: 0x100)
        ns_pkt = Ether() / IP() / TCP(flags=0x100)
        parsed_ns = parse_packet(ns_pkt)
        self.assertEqual(parsed_ns.tcp_flags, ["NS"])
        self.assertEqual(parsed_ns.tcp_flags_hex, 0x100)

    def test_ipv6_and_transport(self):
        """Test IPv6 header extraction and hop limit."""
        pkt = (
            Ether(src="00:aa:bb:cc:dd:ee", dst="00:11:22:33:44:55") /
            IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=128) /
            TCP(sport=49152, dport=80, flags="S")
        )

        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ip_version, 6)
        self.assertEqual(parsed.src_ip, "2001:db8::1")
        self.assertEqual(parsed.dst_ip, "2001:db8::2")
        self.assertEqual(parsed.ttl, 128)  # Hop Limit mapped to ttl
        self.assertEqual(parsed.transport_proto, "TCP")
        self.assertEqual(parsed.dst_port, 80)
        self.assertEqual(parsed.app_proto, "HTTP")

    def test_udp_parsing(self):
        """Test UDP header fields and datagram length."""
        pkt = (
            Ether() /
            IP(src="192.168.1.1", dst="8.8.8.8") /
            UDP(sport=53210, dport=53, len=42)
        )

        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.transport_proto, "UDP")
        self.assertEqual(parsed.src_port, 53210)
        self.assertEqual(parsed.dst_port, 53)
        self.assertEqual(parsed.udp_len, 42)
        self.assertEqual(parsed.app_proto, "DNS")

    def test_icmp_ipv4_parsing(self):
        """Test ICMP Echo Request and Reply parsing."""
        # Echo Request (Type 8, Code 0)
        req_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(type=8, code=0)
        parsed_req = parse_packet(req_pkt)
        self.assertEqual(parsed_req.transport_proto, "ICMP")
        self.assertEqual(parsed_req.icmp_type, 8)
        self.assertEqual(parsed_req.icmp_code, 0)

        # Echo Reply (Type 0, Code 0)
        rep_pkt = Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / ICMP(type=0, code=0)
        parsed_rep = parse_packet(rep_pkt)
        self.assertEqual(parsed_rep.transport_proto, "ICMP")
        self.assertEqual(parsed_rep.icmp_type, 0)
        self.assertEqual(parsed_rep.icmp_code, 0)

    def test_icmpv6_parsing(self):
        """Test ICMPv6 message dissection."""
        pkt = (
            Ether() /
            IPv6(src="fe80::1", dst="fe80::2") /
            ICMPv6EchoRequest(type=128, code=0)
        )

        parsed = parse_packet(pkt)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.ip_version, 6)
        self.assertEqual(parsed.transport_proto, "ICMPv6")
        self.assertEqual(parsed.icmp_type, 128)
        self.assertEqual(parsed.icmp_code, 0)

    def test_arp_request_and_reply(self):
        """Test ARP request and reply header extraction."""
        # ARP Who-has Request (op=1)
        arp_req = Ether(src="aa:bb:cc:dd:ee:01") / ARP(
            op=1,
            hwsrc="aa:bb:cc:dd:ee:01",
            psrc="192.168.1.10",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1"
        )
        parsed_req = parse_packet(arp_req)
        self.assertEqual(parsed_req.transport_proto, "ARP")
        self.assertEqual(parsed_req.arp_op, 1)
        self.assertEqual(parsed_req.arp_src_ip, "192.168.1.10")
        self.assertEqual(parsed_req.arp_dst_ip, "192.168.1.1")
        self.assertEqual(parsed_req.src_ip, "192.168.1.10")
        self.assertEqual(parsed_req.dst_ip, "192.168.1.1")
        self.assertEqual(parsed_req.arp_src_mac, "aa:bb:cc:dd:ee:01")

        # ARP Is-at Reply (op=2)
        arp_rep = Ether(src="aa:bb:cc:dd:ee:02") / ARP(
            op=2,
            hwsrc="aa:bb:cc:dd:ee:02",
            psrc="192.168.1.1",
            hwdst="aa:bb:cc:dd:ee:01",
            pdst="192.168.1.10"
        )
        parsed_rep = parse_packet(arp_rep)
        self.assertEqual(parsed_rep.transport_proto, "ARP")
        self.assertEqual(parsed_rep.arp_op, 2)
        self.assertEqual(parsed_rep.src_ip, "192.168.1.1")
        self.assertEqual(parsed_rep.dst_ip, "192.168.1.10")

    def test_application_protocol_identification(self):
        """Test port-based application protocol tagging for all common protocols."""
        port_expectations = [
            (21, "FTP"),
            (22, "SSH"),
            (25, "SMTP"),
            (53, "DNS"),
            (67, "DHCP"),
            (68, "DHCP"),
            (80, "HTTP"),
            (443, "HTTPS"),
            (3389, "RDP"),
            (8080, "HTTP-ALT"),
        ]

        for port, expected_proto in port_expectations:
            # Client request (destination port)
            client_pkt = Ether() / IP() / TCP(sport=50000, dport=port)
            parsed_client = parse_packet(client_pkt)
            self.assertEqual(parsed_client.app_proto, expected_proto)

            # Server response (source port)
            server_pkt = Ether() / IP() / TCP(sport=port, dport=50000)
            parsed_server = parse_packet(server_pkt)
            self.assertEqual(parsed_server.app_proto, expected_proto)

        # Unmapped port should yield None
        unmapped_pkt = Ether() / IP() / TCP(sport=61234, dport=61235)
        parsed_unmapped = parse_packet(unmapped_pkt)
        self.assertIsNone(parsed_unmapped.app_proto)

    def test_custom_port_mapping(self):
        """Test overriding application protocol mapping with custom dict."""
        custom_map = {9999: "CUSTOM-C2"}
        pkt = Ether() / IP() / TCP(sport=50000, dport=9999)
        parsed = parse_packet(pkt, port_map=custom_map)
        self.assertEqual(parsed.app_proto, "CUSTOM-C2")

    def test_fragmentation_detection(self):
        """Test detection of fragmented packets in IPv4 and IPv6."""
        # 1. IPv4 More Fragments flag (MF)
        pkt_mf = Ether() / IP(flags="MF", frag=0) / TCP()
        parsed_mf = parse_packet(pkt_mf)
        self.assertTrue(parsed_mf.is_fragment)

        # 2. IPv4 Fragment Offset > 0
        pkt_offset = Ether() / IP(frag=10) / TCP()
        parsed_offset = parse_packet(pkt_offset)
        self.assertTrue(parsed_offset.is_fragment)

        # 3. Unfragmented IPv4
        pkt_clean = Ether() / IP() / TCP()
        parsed_clean = parse_packet(pkt_clean)
        self.assertFalse(parsed_clean.is_fragment)

        # 4. IPv6 Fragment Header
        pkt_v6_frag = Ether() / IPv6() / IPv6ExtHdrFragment(offset=1, m=1) / TCP()
        parsed_v6_frag = parse_packet(pkt_v6_frag)
        self.assertTrue(parsed_v6_frag.is_fragment)

    def test_missing_layers_and_malformed_input(self):
        """Test defensive handling of missing layers, non-packet input, and raw frames."""
        # Non-packet object returns None
        self.assertIsNone(parse_packet("string_not_packet"))
        self.assertIsNone(parse_packet(None))
        self.assertIsNone(parse_packet(12345))

        # Pure Ethernet frame with raw bytes (No IP or transport)
        raw_eth = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") / Raw(load=b"\x00\x01\x02")
        parsed_eth = parse_packet(raw_eth)
        self.assertIsNotNone(parsed_eth)
        self.assertEqual(parsed_eth.src_mac, "00:11:22:33:44:55")
        self.assertIsNone(parsed_eth.src_ip)
        self.assertIsNone(parsed_eth.transport_proto)

        # Pure IP packet without transport layer (e.g. IGMP or raw protocol 253)
        pure_ip = Ether() / IP(src="1.1.1.1", dst="2.2.2.2", proto=253)
        parsed_ip = parse_packet(pure_ip)
        self.assertIsNotNone(parsed_ip)
        self.assertEqual(parsed_ip.transport_proto, "OTHER")
        self.assertEqual(parsed_ip.src_ip, "1.1.1.1")
        self.assertIsNone(parsed_ip.src_port)

    def test_to_dict_conversion(self):
        """Verify to_dict() returns a valid dictionary matching all dataclass fields."""
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        parsed = parse_packet(pkt)
        pkt_dict = parsed.to_dict()

        self.assertIsInstance(pkt_dict, dict)
        self.assertIn("timestamp", pkt_dict)
        self.assertIn("packet_size", pkt_dict)
        self.assertIn("src_ip", pkt_dict)
        self.assertIn("dst_ip", pkt_dict)
        self.assertIn("transport_proto", pkt_dict)
        self.assertIn("tcp_flags", pkt_dict)
        self.assertIn("app_proto", pkt_dict)

        self.assertEqual(pkt_dict["src_ip"], "10.0.0.1")
        self.assertEqual(pkt_dict["dst_ip"], "10.0.0.2")
        self.assertEqual(pkt_dict["transport_proto"], "TCP")
        self.assertEqual(pkt_dict["app_proto"], "HTTP")
        self.assertEqual(pkt_dict["tcp_flags"], ["SYN"])

    def test_no_sensitive_payload_stored(self):
        """Verify raw packet payload data is not retained in ParsedPacket."""
        secret_payload = b"SECRET_PASSWORD_12345_TOKEN"
        pkt = Ether() / IP() / TCP() / Raw(load=secret_payload)
        parsed = parse_packet(pkt)

        pkt_dict = parsed.to_dict()
        self.assertNotIn("payload", pkt_dict)
        self.assertNotIn(secret_payload, str(pkt_dict).encode())

    def test_original_scapy_packet_not_modified(self):
        """Verify parsing does not mutate the input Scapy packet."""
        pkt = Ether() / IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1000, dport=80, flags="S")
        pkt_bytes_before = bytes(pkt)

        parse_packet(pkt)
        pkt_bytes_after = bytes(pkt)

        self.assertEqual(pkt_bytes_before, pkt_bytes_after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
