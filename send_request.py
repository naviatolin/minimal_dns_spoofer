""" Construct a DNS A record request and send it. """
from dns_message import Message


def main(dns_address: str = '127.0.0.1') -> bytearray:
    """
    Construct an A record request and send it.

    Parameters
    ----------
    dns_address : str
        string of ipv4 address, set to 127.0.0.1 if none entered

    Returns
    -------
    response : bytearray
        a bytearray of the DNS spoofer response
    """
    # Open a socket and constuct a query
    query = Message(dns_address, 53)
    query.start_socket()
    query.send_query('foo.com')

    # Listen for a response back.
    response, address = query.receive()
    print(response)

    query.socket.close()
    return response


if __name__ == '__main__':
    response = main()
