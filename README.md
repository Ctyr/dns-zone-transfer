#Shell Script to scan DNS Zone Transfer

**Multi-thread** shell script scanner for DNS Zone Transfer vulnerability.

**usage:**./getAXFR.sh domain.list

After run this program, you will get:

	folder/
	├── colleges.list
	├── dnslist
	├── getAXFR.sh
	├── host.txt
	├── log.err
	└── log.txt

- colleges.list : domain list to scan (start with prefix 'www.')
- dnslist : this folder contains dns zone transfer list
- getAXFR.sh : main program
- host.txt : this file contains all dns servers which has zone transfer vulnerability
- log.err : error log
- log.txt : runtime log


The default colleges.list contains thousands of edu.cn domain.

You can get more information from my website:[DNS zone transfer](http://tyr.so/dns-zone-transfer.html)
