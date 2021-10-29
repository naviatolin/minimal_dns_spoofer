""" Listen on the DNS port for any A record request and return a fixed hard coded address. """
from dns_message import Message
import daemon

def main(socket_address: str = '127.0.0.1'):
    """
    Listen for any A record request and return a hard coded address.

    Parameters
    ----------
    socket_address : str
        string of ipv4 address, set to 127.0.0.1 if none entered
    """
    # Open a socket
    response = Message(socket_address, 53)
    response.start_socket()
    response.bind()

    # Continually listen for any A record requests, send back fixed response
    while True:
        try:
            query, address = response.receive()

        except response.socket.timeout:
            continue

        finally:
            response.send_response(query, address)


def launch_daemon():
    """
    Launch a daemon running the process in main().
    """
    with daemon.DaemonContext():
        print("Launched daemon")
        main()


if __name__ == '__main__':
    # launch_daemon()
    main()
