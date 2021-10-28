""" A class for constructing a DNS message given all the parameters. """

# Source for DNS packet construction information: https://datatracker.ietf.org/doc/html/rfc1035#page-26

import socket
import time


class Message():
    def __init__(self, address: str, port: int):
        self.address = address
        self.port = port

    """
    The DNS query header follows the format:
        ID: 16 bit request identifier
            Sent back in the response

        QR: 1 bit query type flag
            0 - query
            1 - response

        Opcode: 4 bit query type
            0 - standard query
            1 - inverse query
            2 - server status request
            3+ - future use

        AA: 1 bit authoritative answer (Response)
            0 - not an authority

        TC: 1 bit truncate bit
            0 - not truncated

        RD: 1 bit recursion flag
            0 - recursion not desired
            1 - recursion desired

        RA: 1 bit recursive available flag (Response)
            Whether or not recursive query support is available

        Z: 3 bits reserved for future use

        RCode: 4 bit response code (Response)
            0 - No error condition
            1 - Format error (unable to interpret)
            2 - Server failure (Name server issue)
            3 - Name error
            4 - Not implemented (Does not support)
            5 - Refused

        QDcount: 16 bit number of questions

        ANcount: 16 bit number of resource records in the answer section

        NScount: 16 bit number of name server resource records in the authority records section

        ARcount: 16 bit number of resource records in the additional records section
    """

    def construct_header(self, identifier, qr, opcode, aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount):
        "Construct a header given all of the individual components."
        # Construct all the bytes individually and then string them together.
        if type(identifier) is not bytes:
            id_upper, id_lower = divmod(identifier, 0x100)
            byte_1_2 = bytearray([id_upper, id_lower])
        else:
            byte_1_2 = identifier

        byte_3 = bytearray([(qr << 7) | (opcode << 3) |
                            (aa << 2) | (tc << 1) | rd])

        byte_4 = bytearray([ra << 8 | z << 4 | rcode])

        if type(qdcount) is not bytes:
            qd_upper, qd_lower = divmod(qdcount, 0x100)
            byte_5_6 = bytearray([qd_upper, qd_lower])
        else:
            byte_5_6 = qdcount

        if type(ancount) is not bytes:
            an_upper, an_lower = divmod(ancount, 0x100)
            byte_7_8 = bytearray([an_upper, an_lower])
        else:
            byte_7_8 = ancount

        if type(nscount) is not bytes:
            ns_upper, ns_lower = divmod(nscount, 0x100)
            byte_9_10 = bytearray([ns_upper, ns_lower])
        else:
            byte_9_10 = nscount

        if type(arcount) is not bytes:
            ar_upper, ar_lower = divmod(arcount, 0x100)
            byte_11_12 = bytearray([ar_upper, ar_lower])
        else:
            byte_11_12 = arcount

        self.header = byte_1_2 + byte_3 + byte_4 + \
            byte_5_6 + byte_7_8 + byte_9_10 + byte_11_12

    """
    The DNS response header follows the same format as the query header.
    """

    def a_record_response_header(self, request: bytearray):
        # Deconstruct query header
        identifier = request[0:2]
        opcode = (request[2] & 0x78) >> 3
        tc = (request[2] & 0x02) >> 1
        rd = (request[2] & 0x01)

        z = (request[3] & 70) >> 4
        rcode = (request[3] & 0x0F)

        qdcount = request[4:6]

        # Construct response header
        qr = 1  # response flag
        aa = 0
        ra = 0
        ancount = 1  # number of responses is 1
        nscount = 0
        arcount = 0

        # If the request is not standard, send back a "not implemented" error
        # TODO: implement error 2 for server failure (error catching)
        # TODO: implement error 1 for format error
        if opcode > 0:
            rcode = 4
        else:
            rcode = 0

        self.construct_header(identifier, qr, opcode, aa, tc,
                              rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

    def a_record_query_header(self):
        identifier = 0xAABB
        qr = 0
        opcode = 0
        aa = 0
        tc = 0
        rd = 1
        ra = 0
        z = 0
        rcode = 0
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0

        self.construct_header(identifier, qr, opcode, aa, tc, rd, ra, z, rcode,
                              qdcount, ancount, nscount, arcount)

    """
    The DNS query question follows the format:
        QName: Contains the URL
            Encoded as a series of labels
            Each section preceded with uint byte containing length
            Terminated with zero byte (00)

        QType: 16 bit DNS record type being used
            1 - A record

        QClass: 16 bit class being looked up
            1 - Internet Class
    """

    def construct_question(self, url: str, qtype, qclass):
        "Generate the query question for a DNS request."
        url = url.split('.')

        qname = bytearray(0)

        for label in url:
            length = bytearray([len(label)])
            label_string = bytearray(label.encode())
            qname = qname + length + label_string

        null_byte = bytearray([0])

        qtype_upper, qtype_lower = divmod(qtype, 0x100)
        qtype_bytes = bytearray([qtype_upper, qtype_lower])

        qclass_upper, qclass_lower = divmod(qclass, 0x100)
        qclass_bytes = bytearray([qclass_upper, qclass_lower])

        self.question = qname + null_byte + qtype_bytes + qclass_bytes

    def a_record_query_question(self, url: str):
        "Construct an A record query question section."
        qtype = 1
        qclass = 1
        self.construct_question(url, qtype, qclass)

    """
    The DNS response answer section has the following format (resource record):
        Name: Compressed name format
            - First two bits are 1
            - Next 14 bits are uint byte offset from beginning of message (12 bytes)

        Type: 16 bit DNS record type being used
            1 - A record

        Class: 16 bit class being looked up
            1 - Internet Class

        TTL: 32 bit uint for time to live for the response
            0 - RR values can only be used for transaction in progress
        
        RDLength: 16 bit uint of the length in octets of the RData field

        RData: 4 octect internet address for A record requests
    """

    def a_record_response_answer(self):
        name = bytearray([(0b11 << 6), 12])
        answer_type = bytearray([0, 1])
        answer_class = bytearray([0, 1])
        ttl = bytearray([0, 0, 0, 0])
        rdlength = bytearray([0, 4])
        rdata = bytearray([6, 6, 6, 6])

        self.answer = name + answer_type + answer_class + ttl + rdlength + rdata

    def start_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def bind(self):
        self.socket.bind((self.address, self.port))

    def send_query(self, url: str):
        self.a_record_query_header()
        self.a_record_query_question(url)
        self.packet = self.header + self.question
        self.socket.sendto(self.packet, (self.address, self.port))

    def receive(self):
        data, address = self.socket.recvfrom(4096)
        return data, address

    def send_response(self, request, address):
        self.a_record_response_header(request)
        self.a_record_response_answer()
        self.packet = self.header + request[12:] + self.answer
        print("Response: ", self.packet)
        self.socket.sendto(self.packet, address)
        print(self.address)
        print(self.port)
        time.sleep(1)
        # self.socket.close()
