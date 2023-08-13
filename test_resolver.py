import unittest
from dns import DNSPacket, DNSHeader, DNSRecord, QType, dns_name
from resolver import resolve

class MockClient:
    def __init__(self):
        self._responses = {}

    def set_response(self, ip_address: str, domain_name: str, record_type: int, response: DNSPacket):
        self._responses[(ip_address, domain_name, record_type)] = response

    def __call__(self, ip_address: str, domain_name: str, record_type: int):
        return self._responses.get((ip_address, domain_name, record_type))


class TestRequest(unittest.TestCase):
    def setUp(self):
        self.client = MockClient()

    def test_recursive_resolve(self):
        self.client.set_response(
            ip_address="198.41.0.4",
            domain_name="example.com",
            record_type=QType.A,
            response=DNSPacket(
              header=DNSHeader(
                id=1,
                num_authorities=1
              ),
              authorities=[
                  DNSRecord(
                    dns_name=dns_name("com"),
                    type_=QType.NS,
                    data="a.iana-servers.net".encode("utf-8")
                  )
              ]
            )
        )

        self.client.set_response(
            ip_address="198.41.0.4",
            domain_name="a.iana-servers.net",
            record_type=QType.A,
            response=DNSPacket(
              header=DNSHeader(
                id=1,
                num_answers=1
              ),
              answers=[
                  DNSRecord(
                    dns_name=dns_name("a.iana-servers.net"),
                    type_=QType.A,
                    data=bytes(int(i) for i in "199.43.135.53".split("."))
                  )
              ]
            )
        )

        self.client.set_response(
            ip_address="199.43.135.53",
            domain_name="example.com",
            record_type=QType.A,
            response=DNSPacket(
              header=DNSHeader(
                id=1,
                num_answers=1
              ),
              answers=[
                  DNSRecord(
                    dns_name=dns_name("example.com"),
                    type_=QType.A,
                    data=bytes(int(i) for i in "93.184.216.34".split("."))
                  )
              ]
            )
        )

        response = resolve(
            domain_name='example.com',
            record_type=QType.A,
            lookup_func=self.client
        )

        self.assertEqual(response, "93.184.216.34")
