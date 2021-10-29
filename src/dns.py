""" Listen on the DNS port for any A record request and return a fixed hard coded address. """
from dns_message import Message
import argparse
import daemon
from daemon import pidfile

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


def launch_daemon(socket_address: str = '127.0.0.1'):
    """
    Launch a daemon running the process in main().

    Parameters
    ----------
    socket_address : str
        string of ipv4 address, set to 127.0.0.1 if none entered
    """
    with daemon.DaemonContext():
        print("Launched daemon")
        main(socket_address)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Minimal DNS Spoofer.')
    parser.add_argument('-address', type=str,
                        default="127.0.0.1", help='address for the DNS socket')

    args = parser.parse_args()

    launch_daemon(args.address)
