import unittest
from response import parse_response, parse_question, parse_record
from dns import DNSHeader, DNSQuestion, DNSRecord
from io import BytesIO

class TestResponse(unittest.TestCase):
    def test_parse_example(self):
        response = b'`V\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00R\x9b\x00\x04]\xb8\xd8"'
        packet = parse_response(response)

        self.assertEqual(
          packet.questions,
          [DNSQuestion(dns_name=b'www.example.com', type_=1, class_=1)]
        )

        self.assertEqual(
           packet.answers,
           [
              DNSRecord(
                dns_name=b'www.example.com',
                type_=1,
                class_=1,
                ttl=21147,
                data=b']\xb8\xd8"'
              )
            ]
        )
