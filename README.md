
DNS Spoofing assignment
------------------------------------
Please write a minimal DNS spoofing daemon for Linux that listens
on the DNS port for any A record request (e.g. foo.com) and returns a
fixed, hard coded address (e.g. 6.6.6.6). Please utilize standard POSIX
socket functions (like open, bind, recvfrom, and sendto) and a
straight-forward approach.

You will be evaluated on the quality of the code as well as its functionality.
We want to see proper error handling, commenting, unit testing, etc. Any
online references should be cited; be aware that we expect the code to be
*your* code.

Example testing steps:

linux box 1:
    # cd your-program-directory    # make    # make check       # we'd love to see at least one test here :)    # ./your-program

linux box 2:
    # dig @linux-box-1 foo.com
    
expected response:
Something like...
    ; <<>> DiG 9.6.1-P2 <<>> @192.168.1.1 foo.com    ; (1 server found)    ;; global options: +cmd    ;; Got answer:    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27387    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0    ;; QUESTION SECTION:    ;foo.com.                       IN      A    ;; ANSWER SECTION:    foo.com.                3600    IN      A 6.6.6.6    ;; Query time: 58 msec    ;; SERVER: 192.168.1.1#53(192.168.1.1)    ;; WHEN: Fri Jan  8 13:23:22 2010    ;; MSG SIZE  rcvd: 41