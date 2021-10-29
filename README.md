
# Minimal DNS Spoofer
A minimal DNS spoofing daemon that listens on the DNS port for an A record request and returns a fixed, hard coded address of ```6.6.6.6```. This project only uses standard POSIX socket functions.

## Setup
To setup necessary libraries run:
```make install```

## Running the Daemon
To launch the DNS spoofing daemon on localhost, run:
```make start```

If you want to launch the daemon on a different IPv4 address, run:
```make start ADDRESS={any other address}```

To kill the DNS spoofing daemon, run:
```make stop```

## Tests
To run tests, run:
```make check```

Once the daemon is running, you can also test using dig. For example:
```dig @127.0.0.1 google.com```

You will see the DNS spoofer return 6.6.6.6 each time. Corresponding Response:
```
; <<>> DiG 9.10.6 <<>> @127.0.0.1 google.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63867
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             0       IN      A       6.6.6.6

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Fri Oct 29 12:51:41 EDT 2021
;; MSG SIZE  rcvd: 44
```