import pytest

# ---------------------------------------------------------------------------- #
#                              Testing DNS Message                             #
# ---------------------------------------------------------------------------- #

from dns_message import Message

dns = Message(socket_address, 53)
dns.start_socket()
dns.bind()

def test_query_header_1():
    assert ()