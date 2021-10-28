from dns_message import Message


def main():
    query = Message('127.0.0.1', 53)
    query.start_socket()
    query.send_query('foo.com')

    response, address = query.receive()

    query.socket.close()
    print(response)


if __name__ == '__main__':
    main()
