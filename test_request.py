import unittest
from request import build_query
from dns import QType

class TestRequest(unittest.TestCase):
    def test_google_a_query(self):
        query = build_query(id=17611, domain_name="example.com", record_type=QType.A)
        self.assertEqual(query, b'D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01')

if __name__ == '__main__':
    unittest.main()
