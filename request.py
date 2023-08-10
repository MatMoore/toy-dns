
import random
import socket
from dns import dns_name, DNSHeader, DNSQuestion, Flag, Class

def build_query(id, domain_name, record_type):
    name = dns_name(domain_name)
    header = DNSHeader(id=id, flags=Flag.RECURSION_DESIRED, num_questions=1)
    question = DNSQuestion(dns_name=name, type_=record_type, class_=Class.IN)

    return header.pack() + question.pack()


def generate_id():
    return random.randint(0, 65535)


if __name__ == '__main__':
    id = generate_id()
    query = build_query(id=id, domain_name="www.example.com", record_type=QType.A)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    # read the response. UDP DNS responses are usually less than 512 bytes
    # (see https://www.netmeister.org/blog/dns-size.html for MUCH more on that)
    # so reading 1024 bytes is enough
    response, _ = sock.recvfrom(1024)
