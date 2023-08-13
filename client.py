from request import build_query, generate_id
from response import parse_response
import socket


def send_query(ip_address, domain_name, record_type):
  """
  Send a query to an authorititive nameserver.
  """
  query = build_query(generate_id(), domain_name, record_type, flags=0)
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.sendto(query, (ip_address, 53))

  data, _ = sock.recvfrom(1024)
  return parse_response(data)
