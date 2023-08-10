import unittest
from dns import DNSHeader, DNSQuestion, encode_dns_name, build_query, QType

class TestPart1(unittest.TestCase):
    def test_pack_header(self):
        header = DNSHeader(
            id=0x1314,
            num_questions=1
        )
        self.assertEqual(
            header.pack(),
            b'\x13\x14\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        )

    def test_pack_question(self):
        pass

    def test_encode_google(self):
        domain = "google.com"
        encoded = encode_dns_name(domain)
        self.assertEqual(encoded, b"\x06google\x03com\x00")

    def test_google_a_query(self):
        query = build_query(id=17611, domain_name="example.com", record_type=QType.A)
        self.assertEqual(query, b'D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01')

if __name__ == '__main__':
    unittest.main()
