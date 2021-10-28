"Listen on the DNS port for any A record request."
from dns_message import Message

response = Message('127.0.0.1', 53)
response.start_socket()
response.bind()

while True:
    try:
        query, address = response.receive()

    except response.socket.timeout:
        continue
    finally:
        print('Got {} bytes from {}'.format(len(query), address))
        response.send_response(query, address)
        # response.start_socket()
        # response.bind()
