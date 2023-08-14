"""
A toy DNS resolver, that resolves domain names to IP addresses by recursively
querying nameservers.

This does minimal validation of the records returned by the nameservers.
"""
import socket
import sys
from request import build_query, generate_id
from response import parse_response
from formatting import ip_to_string
from dns import QType


ROOT_NAMESERVER = '198.41.0.4'


def first_a_record(records):
    for record in records:
        if record.type_ == QType.A:
            return record.data


def first_ns_record(records):
    for record in records:
        if record.type_ == QType.NS:
            return record.data.decode('utf-8')


def get_answer(packet):
    return first_a_record(packet.answers)


def get_nameserver_ip(packet, lookup_func):
    if ip := first_a_record(packet.additionals):
        return ip_to_string(ip)
    elif ns := first_ns_record(packet.authorities):
        return resolve(ns, QType.A, lookup_func=lookup_func)


def resolve(domain_name, record_type, nameserver=ROOT_NAMESERVER, lookup_func=send_query):
    """
    Query an authoritive nameserver.
    """
    print(f"Resolving {domain_name} via {nameserver}")
    response = lookup_func(nameserver, domain_name, record_type)
    if ip := get_answer(response):
        return ip_to_string(ip)
    elif nameserver_ip := get_nameserver_ip(response, lookup_func):
        return resolve(domain_name, record_type, nameserver=nameserver_ip, lookup_func=lookup_func)
    else:
        raise Exception(f"No records found for {domain_name} {record_type}")


def lookup_domain(domain_name):
    """
    Look up the IP address for a domain
    """
    query = build_query(generate_id(), domain_name, QType.A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(query, ("8.8.8.8", 53))

    data, _ = sock.recvfrom(1024)
    response = parse_response(data)
    answers = [a for a in response.answers if a.type_ == QType.A]

    return ip_to_string(answers[0].data)


if __name__ == '__main__':
    print(resolve(sys.argv[1], QType.A))
