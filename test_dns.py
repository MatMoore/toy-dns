import unittest
from dns import DNSHeader, dns_name

class TestDNS(unittest.TestCase):
    def test_pack_header(self):
        header = DNSHeader(
            id=0x1314,
            num_questions=1
        )
        self.assertEqual(
            header.pack(),
            b'\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        )

    def test_encode_google(self):
        domain = "google.com"
        encoded = dns_name(domain)
        self.assertEqual(encoded, b"\x06google\x03com\x00")


if __name__ == '__main__':
    unittest.main()
