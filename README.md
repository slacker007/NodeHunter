# NodeHunter
The nodehunter module is a Python based executable that takes advantage of the NMAP API to perform a field expedient method of interrogating the cyberspace terrain for live nodes, ports, and services. It is loud and meant to provide the most holistic picture of the terrain. The follow types of node discovery are conducted: ARP, TCP SYN, TCP ACK, UDP, SCTP INIT, ICMP Echo Request, ICMP Timestamp Request, ICMP Address Mask Query, and IP Protocol Discovery. When executing with -a it utilizes all of the aforementioned discovery scans, plus a Full TCP Connect Scan of all 65,535 TCP ports of each unique IP, and Service Enumeration on each unique open port.
***requirements***
```
- Python 2.7.x
- neo4jrestclient
- Python-nmap
```

***usage: nodehunter.py [-h] [-n] [-a] [-s]***
```
optional arguments:
  -h, --help      show this help message and exit
  -n, --nodes     only perforom node discovery
  -a, --allscans  perform node, service and port discovery
  -s, --scanonly  perform scan only and print results to screen. Do not injest into DB
```
<strong>EXAMPLE</strong>
```
 mercenary@ubuntu:~/nodehunter$ sudo ./nodehunter.py --nodes --scanonly
 Please enter a target address/range/CIDR: 192.168.1.0/24
 Running arp Scan..
 [+] Found: 192.168.1.1 
 [+] Found: 192.168.1.254 
 [+] Found: 192.168.1.68 
 [+] Found: 192.168.1.69 
 [+] Found: 192.168.1.70 
 [+] Found: 192.168.1.71 
 [+] Found: 192.168.1.74 
 [+] Found: 192.168.1.75 
 [+] Found: 192.168.1.78 
 [+] Found: 192.168.1.82 
 [+] Found: 192.168.1.85 
 [+] Found: 192.168.1.87 
 [+] Found: 192.168.1.89 
 [+] Found: 192.168.1.92 
 Running tcpsyn Scan..
 [+] Found: 192.168.1.64 
 [+] Found: 192.168.1.76 
 [+] Found: 192.168.1.81 
 Running tcpack Scan..
 Running udp Scan..
 [+] Found: 192.168.1.67 
 Running sctp Scan..
 Running icmp_echo Scan..
 Running icmptime Scan..
 [+] Found: 192.168.1.66 
 Running icmpaddrmsk Scan..
 Running ipp Scan..
 [+] Total Nodes: 19 
```
