install:
	pip install -r requirements.txt

ADDRESS := 127.0.0.1
start:
	sudo python src/dns.py -address $(ADDRESS)

check:
	pytest src/test.py -v

stop: 
	sudo pkill -9 -f src/dns.py