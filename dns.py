from dataclasses import dataclass
import struct
import socket
import random
from enum import IntEnum

class Flag(IntEnum):
    RECURSION_DESIRED = 1 << 8


class Class(IntEnum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class QType(IntEnum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MX = 15
    TXT = 16
    AXFR = 252
    MAILB = 253
    MAILA = 254
    ALL = 255


@dataclass
class DNSHeader:
    """
     00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | id |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR| Opcode |AA|TC|RD|RA| Z | RCODE |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | num_questions                                 |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | num_answers                                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | num_authorities                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | num_additionals                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    """
    id: int # 16 bit identifier used to correlate request/reply
    flags: int = 0 # we are ignoring this!
    num_questions: int = 0 # number of entries in the question section
    num_answers: int = 0 # number of entries in the answers section
    num_authorities: int = 0 # number of nameserver records in the authority records section
    num_additionals: int = 0 # number of resource records in the additional records section

    def pack(self):
        """
        Encode into a big-endian bytestring
        """
        return struct.pack(
            "!HHHHHH",
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals
        )


@dataclass
class DNSQuestion:
    name: bytes
    type_: int
    class_: int

    def pack(self):
        """
        Encode into a big-endian bytestring
        """
        return self.name + struct.pack(
            "!HH",
            self.type_,
            self.class_
        )


def encode_dns_name(domain_name):
    """
    Domain names are represented as a sequence of labels,
    where each label consists of a length octet followed by that
    number of octets. (https://www.ietf.org/rfc/rfc1035.txt)
    """
    result = bytearray()
    for label in domain_name.encode("ascii").split(b"."):
        try:
            result.append(len(label))
        except ValueError as e:
            raise ValueError("Label must be less than 256 characters") from e

        result.extend(label)

    # The domain name terminates with the zero length octet for the null label
    # of the root.
    result.append(0)

    return bytes(result)


def build_query(id, domain_name, record_type):
    name = encode_dns_name(domain_name)
    header = DNSHeader(id=id, flags=Flag.RECURSION_DESIRED, num_questions=1)
    question = DNSQuestion(name=name, type_=record_type, class_=Class.IN)

    return header.pack() + question.pack()


if __name__ == '__main__':
    id = random.randint(0, 65535)
    query = build_query(id=id, domain_name="www.example.com", record_type=QType.A)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # read the response. UDP DNS responses are usually less than 512 bytes
    # (see https://www.netmeister.org/blog/dns-size.html for MUCH more on that)
    # so reading 1024 bytes is enough
    response, _ = sock.recvfrom(1024)
