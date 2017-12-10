from scapy.all import *
import argparse
import socket
from collections import deque
import datetime

data = deque(maxlen=100)

def intersection(pkt1, pkt2):
	for i in range(0, pkt1[DNS].ancount):
		for j in range(0, pkt2[DNS].ancount):
			if (pkt1[DNSRR][i].type == 1 and pkt2[DNSRR][j].type == 1 and
				pkt1[DNSRR][i].rdata == pkt2[DNSRR][j].rdata):
				return True
	return False;

def printPackets(pkt1, pkt2):

	l1 = []
	for i in range(0, pkt1[DNS].ancount):
		if (pkt1[DNSRR][i].type == 1):
			l1.append(pkt1[DNSRR][i].rdata)

	l2 = []
	for i in range(0, pkt2[DNS].ancount):
		if (pkt2[DNSRR][i].type == 1):
			l2.append(pkt2[DNSRR][i].rdata)

   	if len(l1) == 0 and len(l2) == 0:
   		return

	print datetime.datetime.fromtimestamp(pkt1.time).strftime("%Y%m%d-%H:%M:%S.%f"),
	print " DNS poisoning attempt"
	print "TXID " + format(pkt1[DNS].id, "X") + \
	      "  Request " + pkt1[DNSQR].qname
	print "Answer1  " + str(l1)
	print "Answer2  " + str(l2)
	print "\n\n"

def insert(pkt):
	for prevPkt in data:
		if (prevPkt[DNS].id == pkt[DNS].id):
			return;

	data.append(pkt)

def detect(pkt):
	if (pkt.haslayer(DNSQR) and
		pkt[DNS].qr == 1 and 
		pkt[DNSQR].qtype == 1):
		#print data
		for prevPkt in data:
			if (pkt[DNS].id == prevPkt[DNS].id and
				pkt[IP].dst == prevPkt[IP].dst and
				pkt[UDP].dport == prevPkt[UDP].dport and
				pkt[DNSQR].qname == prevPkt[DNSQR].qname):

				if (not intersection(pkt[DNS], prevPkt[DNS]) or
					pkt[IP].ttl != prevPkt[IP].ttl or
					pkt[Ether].src != prevPkt[Ether].src):
					printPackets(pkt, prevPkt)
		
		insert(pkt)

parser = argparse.ArgumentParser(description="dnsdetect", add_help=False)
parser.add_argument("-i", help="interface")
parser.add_argument("-r", help="trace_file")
parser.add_argument("expression", nargs="*", help="filter")
args = parser.parse_args()

			
#print victims
bpf = "udp port 53"
if args.expression:
	exp = " ".join(args.expression)
	bpf = bpf + " and " + "(" + exp + ")" 
#print bpf
print args.r
if args.i is None:
	if args.r is None:
		sniff(filter=bpf, prn=detect)
	else:
		sniff(filter=bpf, prn=detect, offline=args.r)
else:
	if args.r is None:
		sniff(filter=bpf, iface=args.i, prn=detect)
	else:
		sniff(filter=bpf, iface=args.i, prn=detect, offline=args.r)