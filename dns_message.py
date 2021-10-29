""" A class for constructing a DNS messages for A record requests. """

import socket

# Source for DNS packet construction information: https://datatracker.ietf.org/doc/html/rfc1035#page-26


class Message():
    """
    A class used to construct, send, and receive packets for DNS requests and responses.

    ...
    Attributes
    ----------
    address : str
        an ipv4 address

    port : int
        port number 

    Methods
    -------
    a_record_query_header()
        Generates a predetermined A record request header.

    a_record_response_header(request)
        Generates a DNS response header based on a provided A record request.

    _construct_header(self, response_flag, identifier, qr, opcode, 
        aa, tc, rd, ra, z, rcode, qdcount, ancount, nscount, arcount)
        Returns a header given all the parameters required.

    a_record_query_question(url):
        Constructs A record request question section.

    _construct_question(url, qtype, qclass)
        Generates a DNS question section given all the parameters.

    parse_query_question(query)
        Returns the ending index to the question section in a given A record request.

    a_record_response_answer()
        Returns a constructed answer section to spoof DNS responses. 

    start_socket()
        Starts a socket for IPv4.

    bind()
        Binds a socket to a specific address and port.

    send_query(url)
        Given a URL construct a A record request and send it.

    receive()
        Receive data from a socket.

    send_response(request, address)
        Construct a DNS response and send it to the same address the request was received from.
    """

    def __init__(self, address: str, port: int):
        """
        Parameters
        ----------
        address : str
            IPv4 address
        port : int
            port number
        """
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

        AA: 1 bit authoritative answer (For response)
            0 - not an authority

        TC: 1 bit truncate bit
            0 - not truncated

        RD: 1 bit recursion flag
            0 - recursion not desired
            1 - recursion desired

        RA: 1 bit recursive available flag (For response)
            Whether or not recursive query support is available

        Z: 3 bits reserved for future use

        RCode: 4 bit response code (For response)
            0 - No error condition
            1 - Format error
            2 - Server failure 
            3 - Name error
            4 - Not implemented
            5 - Refused

        QDcount: 16 bit number of questions

        ANcount: 16 bit number of resource records in the answer section

        NScount: 16 bit number of name server resource records in the authority records section

        ARcount: 16 bit number of resource records in the additional records section
    """

    def a_record_query_header(self) -> bytearray:
        """
        Generate a header for an A record DNS query.

        This header can be used for testing later on.

        Returns
        -------
        header : bytearray
            bytearray of the constructed header
        """
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

        header = self._construct_header(False, identifier, qr, opcode, aa, tc, rd, ra, z, rcode,
                                        qdcount, ancount, nscount, arcount)
        return header

    """
    The DNS response header follows the same format as the query header.
    """

    def a_record_response_header(self, request: bytearray) -> bytearray:
        """
        Generate a header for a DNS response.

        Parameters
        ----------
        request : bytearray
            received DNS query

        Returns
        -------
        header : bytearray
            bytearray of the constructed header
        """
        # Deconstruct the query header
        identifier = request[0:2]
        opcode = (request[2] & 0x78) >> 3
        tc = (request[2] & 0x02) >> 1
        rd = (request[2] & 0x01)

        z = (request[3] & 70) >> 4
        rcode = (request[3] & 0x0F)

        qdcount = request[4:6]

        # Prepare other parameters for the response header
        qr = 1  # Set to high because it is a response
        aa = 0
        ra = 1  # This is not true; otherwise dig throws warning

        ancount = 1  # Number of responses
        nscount = 0
        arcount = 0

        # If the request is non-standard set the opcode to "not implemented"
        if opcode > 0:
            rcode = 4
        else:
            rcode = 0

        # Contruct a header
        header = self._construct_header(True, identifier, qr, opcode, aa, tc,
                                        rd, ra, z, rcode, qdcount, ancount, nscount, arcount)

        return header

    def _construct_header(self, response_flag: bool, identifier, qr, opcode, aa, tc, rd, ra,
                          z, rcode, qdcount, ancount, nscount, arcount) -> bytearray:
        """
        Construct a header given all of the required components.

        Parameters
        ----------
        response_flag : bool
            flag indicating whether or not the header is for a response
        identifier : int or bytearray
            DNS header identifier
        qr : int
            query or response flag
        opcode : int
            DNS header opcode
        aa : int
            authoritative answer
        tc : int
            truncation flag
        rd : int
            recursion desired
        ra : int
            recursion available
        z : int
            reserved for future use and must be zero always
        rcode : int
            response code
        qdcount : int or bytearray
            number of entries in question section
        ancount : int
            number of entries in resource records of answer section
        nscount : int
            number of name server records in authority records section
        arcount : int
            number of resource records in additional records section

        Returns
        -------
        header : bytearray
            final constructed header
        """

        # Construct bytes from all parameters that cannot be a bytearray.
        byte_3 = bytearray([(qr << 7) | (opcode << 3) |
                            (aa << 2) | (tc << 1) | rd])

        byte_4 = bytearray([ra << 7 | z << 4 | rcode])

        an_upper, an_lower = divmod(ancount, 0x100)
        byte_7_8 = bytearray([an_upper, an_lower])

        ns_upper, ns_lower = divmod(nscount, 0x100)
        byte_9_10 = bytearray([ns_upper, ns_lower])

        ar_upper, ar_lower = divmod(arcount, 0x100)
        byte_11_12 = bytearray([ar_upper, ar_lower])

        # If the header is for a request convert to bytearray
        if response_flag is False:
            id_upper, id_lower = divmod(identifier, 0x100)
            byte_1_2 = bytearray([id_upper, id_lower])

            qd_upper, qd_lower = divmod(qdcount, 0x100)
            byte_5_6 = bytearray([qd_upper, qd_lower])

        else:
            byte_1_2 = identifier
            byte_5_6 = qdcount

        # Concatenate all the pieces of the header together
        header = byte_1_2 + byte_3 + byte_4 + \
            byte_5_6 + byte_7_8 + byte_9_10 + byte_11_12

        return header

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

    def a_record_query_question(self, url: str):
        """
        Construct an A record query question section.

        Parameters
        ----------
        url : str
            string of the url in the request
        """
        qtype = 1
        qclass = 1
        question = self._construct_question(url, qtype, qclass)
        return question

    def _construct_question(self, url: str, qtype: int, qclass: int) -> bytearray:
        """
        Generate the question section for a A record DNS request.

        Parameters
        ----------
        url : str
            string of the url in the request
        qtype : int
            DNS record type, should always be 1
        qclass : int
            class being looked up, should always be 1

        Returns
        -------
        question : bytearray
            final constructed question section
        """
        # Convert a url into distinct labels
        url = url.split('.')

        qname = bytearray(0)

        for label in url:
            length = bytearray([len(label)])
            label_string = bytearray(label.encode())
            qname = qname + length + label_string

        null_byte = bytearray([0])

        # qtype byte construction
        qtype_upper, qtype_lower = divmod(qtype, 0x100)
        qtype_bytes = bytearray([qtype_upper, qtype_lower])

        # qclass byte construction
        qclass_upper, qclass_lower = divmod(qclass, 0x100)
        qclass_bytes = bytearray([qclass_upper, qclass_lower])

        # Concatenate the final question section
        question = qname + null_byte + qtype_bytes + qclass_bytes

        return question

    def parse_query_question(self, query: bytearray) -> int:
        """
        Find the index to the end of the question section given a request.

        Parameters
        ----------
        query : bytearray
            received A record request 

        Returns
        -------
        i : int
            ending index to the question section of the index
        """

        search = True
        i = 12

        # Iterate through the request until the null byte is found,
        while search is True:
            length = int(query[i])
            i = i + length + 1
            if length is 0:
                search = False
                i = i + 4
        stop = i + 12
        return i

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

    def a_record_response_answer(self) -> bytearray:
        """
        Construct an A record response to the request with constant rdata.

        Returns
        -------
        answer : bytearray
            constructed answer section bytes for DNS response
        """
        name = bytearray([(0b11 << 6), 12])
        answer_type = bytearray([0, 1])
        answer_class = bytearray([0, 1])
        ttl = bytearray([0, 0, 0, 0])
        rdlength = bytearray([0, 4])
        rdata = bytearray([6, 6, 6, 6])

        answer = name + answer_type + answer_class + ttl + rdlength + rdata
        return answer

    def start_socket(self):
        """
        Starts a socket for IPv4.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def bind(self):
        """
        Binds a socket to a specific address and port.
        """
        self.socket.bind((self.address, self.port))

    def send_query(self, url: str):
        """
        Given a URL construct a A record request and send it.

        Parameters
        ----------
        url : str
            string of the requested URL
        """
        # Create the header and question sections
        header = self.a_record_query_header()
        question = self.a_record_query_question(url)

        # Construct the packet and sent it
        packet = header + question
        self.socket.sendto(packet, (self.address, self.port))

    def receive(self):
        """
        Receive data from a socket.

        Returns
        -------
        data : bytearray
            bytearray of the data received
        address : int
            address the data was received from
        """
        data, address = self.socket.recvfrom(4096)
        return data, address

    def send_response(self, request, address):
        """
        Construct a DNS response and send it to the same address the request was received from.

        Parameters
        ----------
        request : bytearray
            A record request received
        address : int
            address the request was received from
        """
        header = self.a_record_response_header(request)
        question_stop = self.parse_query_question(request)
        answer = self.a_record_response_answer()

        packet = header + request[12: question_stop] + answer
        self.socket.sendto(packet, address)
