from dns import DNSHeader, DNSQuestion, DNSRecord, DNSPacket, QType
from io import BytesIO
import struct

def parse_response(response_bytes):
    """
    Parse a DNS response
    """
    reader = BytesIO(response_bytes)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)


def parse_header(reader):
    """
    Parse the header within a DNS packet
    """
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)


def decode_name(reader):
    """
    Decode a domain name, taking into account DNS compression
    """
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            # If the top bytes are 1s, we have a pointer rather than the name itself.
            byte1 = length & 0b0011_1111
            byte2 = reader.read(1)[0]
            pointer = struct.unpack("!H", bytes([byte1, byte2]))[0]
            parts.append(decode_name_from_pointer(reader, pointer))
            break
        else:
          parts.append(reader.read(length))

    return b".".join(parts)


def decode_name_from_pointer(reader, pointer):
    """
    When compression is used, the name is read from elsewhere in the
    packet.
    """
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)

    return result


def parse_question(reader):
    """
    Parse a question from a DNS packet
    """
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(dns_name = name, type_=type_, class_=class_)


def parse_record(reader):
    """
    Parse a record from the answer/authoritity/additional section
    within a DNS packet.
    """
    name = decode_name(reader)

    # the the type, class, TTL, and data length together are 10 bytes (2 + 2 + 4 + 2 = 10)
    # so we read 10 bytes
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data)

    if type_ == QType.NS:
      data = decode_name(reader)
    else:
      data = reader.read(data_len)

    return DNSRecord(name, type_, class_, ttl, data)
