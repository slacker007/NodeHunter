#! /usr/bin/env python
'''This Script is a built in tool that comes with Mercenary-Linux and/or 
   MercenaryHuntFramework
   created by slacker007 of cybersyndicates
   @real_slacker007
'''
from neo4jrestclient.client import GraphDatabase
from neo4jrestclient import client
from termcolor import colored
from getpass import getpass
import nmap
import sys
import time
import argparse

def main(args):
    '''
    Main() 
    Execution Control
    '''
    l = discscan(get_target()) # uses nmap api to disover nodes
    if args.scanonly:
        pass
    else:
        gdb = create_session() # establishes communication & session w/ db

    if args.nodes:
        if args.scanonly:
            pass
        else:
            load_d1_data(l, gdb)        
    elif args.allscans:
        ml = portscans(l)
        if args.scanonly:
            pass
        else:
            load_d3_data(ml, gdb)
            return 0
    else:
        return 1
def create_session():
    '''
    Gets IP of server & returns session token
    '''
    neoip = "0"
    neoip = raw_input('Enter IP of neo4j DB or press [ENTER] for localhost: ')
    if neoip == '':
        print "Using 'localhost' "
        neoip = 'localhost'
    neoun = "0"
    neoun = raw_input('Enter neo4j DB username or press [ENTER] for neo4j: ')
    if len(neoun) == 0:
	neoun = "neo4j"
    addr = 'https://' + neoip + ':7473/db/data/'
    gdb = GraphDatabase(addr, username=neoun, password=getpass('Enter neo4j password: '))
    return gdb
def get_target():
    '''
    Gets the address that is to be scanned from user
    and returns it as a string
    '''
    target = raw_input("Please enter a target address/range/CIDR: ")
    return target

def discscan(target):
    '''
    Takes in a target network address as a string and runs a series of 
    nmap scans against it.  Returns a list of targets with no 
    duplicates.
    '''
    scan_types = [('arp', '-n -sn -PR --max-rtt-timeout 250ms'), \
            ('tcpsyn', '-n -sn -PS22-25,53,80,111,135,443,445 --max-rtt-timeout 250ms'),\
            ('tcpack', '-n -sn -PA22-25,53,80,111,135,443,445 --max-rtt-timeout 250ms'), \
            ('udp', '-n -sn -PU53,123,137,500,200,2001,4500,5355,6129,40125,65133 --max-rtt-timeout 250ms'), \
            ('sctp', '-n -sn -PY22-25,53,80,111,113,1050,3500 --max-rtt-timeout 250ms'), \
            ('icmp_echo', '-n -sn -PE --max-rtt-timeout 250ms'), \
            ('icmptime', '-n -sn -PP --max-rtt-timeout 250ms'), \
            ('icmpaddrmsk', '-n -sn -PM --max-rtt-timeout 250ms'), \
            ('ipp', '-n -sn -PO --max-rtt-timeout 250ms')]
    scansl = []
    templist = []
    for val in scan_types:
        ps = nmap.PortScanner()
	print("Running %s Scan.." % (val[0]))
	if (val[0] == 'arp'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'tcpsyn'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'tcpack'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'udp'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'sctp'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'icmp_echo'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'icmptime'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'icmpaddrmsk'):
	    ps.scan(hosts=target, arguments=val[1])
	elif (val[0] == 'ipp'):
	    ps.scan(hosts=target, arguments=val[1])
	templist = ps.all_hosts()
	
	for ip in templist:
		if ip not in scansl:
			print colored("[+] Found: {0} ".format(ip), 'red')
			scansl.append(ip)
    print colored("[+] Total Nodes: {0} ".format(len(scansl)), 'red')
    return scansl

def portscans(targetlist):
    '''
    This Function takes in a list of IP's and runs
    a port & service scan on them.
    It returns a list of 3-item tuples
    Example return: [('10.0.0.1', [22, 53, 443], [ssh, domain, https])]
    '''
    main_list_of_tuples = []
    port_svc = nmap.PortScanner()
    for target in targetlist:
        print colored("[+] PERFORMING PORT & SRV SCAN ON: {0}".format(target), 'green')
        port_svc.scan(hosts=target, arguments='-Pn -n -sT -sV -r -p1-5535 --max-rtt-timeout 10ms')
        for host in port_svc.all_hosts():
	    slist = []
            chost = host
            for proto in port_svc[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(port_svc[host][proto].keys())
                lport.sort()
                for port in lport:
		    if (port_svc[host][proto][port]['name'] == ''):
		        slist.append('UNKNOWN')
		    else:
                        slist.append(port_svc[host][proto][port]['name'])
                main_list_of_tuples.append((chost, lport, slist))
    return main_list_of_tuples

def load_d1_data(main_list, gdb):
    '''
    Takes a list of nodes and enters them into database
    '''
    label = 'DISCOVERED_NODES'
    nlabel = gdb.labels.create(label)
    
    try:
        check = gdb.labels.get(label)
    except:
        nullval = gdb.node.create(ip='NULL')
        nlabel.add(nullval)
        time.sleep(5) 
        check = gdb.labels.get(label)
    
    for node in main_list:
        test = check.get(ip=node)
        if (len(test) == 0):
            hnode = gdb.nodes.create(ip=node)
            nlabel.add(hnode)
        else:
            continue
    return 

def load_d3_data(main_list, gdb):
    '''
    Takes a list of 3-item tuples in as an argument
    Inserts IP into list w/ ports & services 
    Forms relationships between every node running a service
    '''
#   gdb = GraphDatabase("https://localhost:7473/db/data/", username='neo4j', password='password')
    label = 'D3_' + time.strftime('%H%M')
    ports = gdb.labels.create("PORTS")
    services = gdb.labels.create("SERVICES")
    nodelabel = gdb.labels.create(label)
    
    #Needed Because labels don't exist until a Node is added
    nullval = gdb.node.create(port='NULL')
    ports.add(nullval)
    nullval = gdb.node.create(service='NULL')
    services.add(nullval)
    
    #Test For value DB - 2nd half of this does
    #the check in the second for loop below
    check = gdb.labels.get("PORTS")
    for item in main_list:
        hnode = gdb.nodes.create(host=item[0], PORTS=item[1], SERVICES=item[2])
        nodelabel.add(hnode)
        for i in range(len(item[1])):
            test = check.get(port=item[1][i])
            if (len(test) == 0):
                print "Adding Port: {:<}".format(item[1][i])
                print "Adding Service: {:<}".format(item[2][i])
                hport = gdb.nodes.create(port=item[1][i])
                hservice = gdb.nodes.create(service=item[2][i])
                ports.add(hport)
                services.add(hservice)
                #____Relationships____
                hservice.Running_On_Port(hport)
            else:
                continue
#Build Addtl Relationships between Nodes
    lName = 'SERVICES'
    q = "MATCH (n: {0}) RETURN n".format(lName)
    q2 = "MATCH (n2: {0}) RETURN n2".format(label)
    sq = gdb.query(q=q)
    nq = gdb.query(q=q2)

    for svc in sq:
        s_id = svc[0]['metadata']['id']
        s_val = svc[0]['data']['service']
        if (s_val == 'NULL'):
            continue
        else:
            for e_node in nq:
                n_id = e_node[0]['metadata']['id']
                n_list_of_val = e_node[0]['data']['SERVICES']
                for val in n_list_of_val: # chk for 'service' in l of svcs
                    if (str(s_val) == str(val)):
                        rel_name = 'Is_Running'
                        n1 = gdb.node[n_id]
                        n2 = gdb.node[s_id]
                        r = gdb.relationships.create(n1, rel_name, n2)
    return 

if __name__ == "__main__":
    #parse arguments from cli
    if len(sys.argv) < 2:
        print "Error: Too Few Arguments"
        print "<command> --help"
        sys.exit()
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', '--nodes', help='\tonly perforom node discovery', action='store_true')
    parser.add_argument('-a', '--allscans', help='\tperform node, service and port discovery ', action='store_true')
    parser.add_argument('-s', '--scanonly', help='\tperform scan only and print results to screen. Do not injest into DB', action='store_true')
    args = parser.parse_args()

    main(args)

