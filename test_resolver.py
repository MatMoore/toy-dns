import unittest
from dns import DNSPacket, DNSHeader, DNSRecord, QType, dns_name
from resolver import resolve, ROOT_NAMESERVER

class MockClient:
    def __init__(self):
        self._responses = {}

    def set_response(self, ip_address: str, domain_name: str, record_type: int, response: DNSPacket):
        self._responses[(ip_address, domain_name, record_type)] = response

    def __call__(self, ip_address: str, domain_name: str, record_type: int):
        try:
          return self._responses[(ip_address, domain_name, record_type)]
        except KeyError:
            raise ValueError(f"Mock response not set for {ip_address=}, {domain_name=}, {record_type=}")


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
                    data=b"a.iana-servers.net"
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

    def test_resolve_alias(self):
      self.client.set_response(
        ip_address=ROOT_NAMESERVER,
        domain_name="www.facebook.com",
        record_type=QType.A,
        response=DNSPacket(
          header=DNSHeader(
            id=27295,
            num_answers=1
          ),
          answers=[
            DNSRecord(
              dns_name=b'www.facebook.com',
              type_=5,
              class_=1,
              ttl=3600,
              data=b"star-mini.c10r.facebook.com"
            )
          ]
        )
      )

      self.client.set_response(
        ip_address=ROOT_NAMESERVER,
        domain_name="star-mini.c10r.facebook.com",
        record_type=QType.A,
        response=DNSPacket(
          header=DNSHeader(
            id=27295,
            num_answers=1
          ),
          answers=[
            DNSRecord(
              dns_name=b'star-mini.c10r.facebook.com',
              type_=1,
              ttl=3600,
              data=bytes(int(i) for i in "157.240.221.35".split("."))
            )
          ]
        )
      )

      response = resolve(
          domain_name="www.facebook.com",
          record_type=QType.A,
          lookup_func=self.client,
          nameserver=ROOT_NAMESERVER
      )

      self.assertEqual(response, "157.240.221.35")
