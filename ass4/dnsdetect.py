from scapy.all import *
import argparse
import socket

data = dequeue(maxlen=100)

def intersection(pkt1, pkt2):
	for x in pkt1[DNS].an:
		for y in pkt2[DNS].an:
		if x.rdata == y.rdata
			return True;

	return False;

def printPackets(pkt1, pkt2):
	print pkt1.time + " DNS poisoning attempt"
	l1 = []
	for x in pkt1[DNS].an:
		l1.append(x.rdata)

	l2 = []
	for x in pkt2[DNS].an:
		l2.append(x.rdata)

	print Answer1 + "  " + l1
	print Answer2 + "  " + l2


def detect(pkt):
	if (pkt.haslayer(DNSQR) and
		pkt[DNS].qr == 1 and 
		pkt[DNSQR].qtype == 1):

		for prevPkt in data:
			if (pkt[DNS].id == prevPkt[DNS].id and
				pkt[IP].dst == prevPkt[IP].dst and
				pkt[UDP].dport == prevPkt[UDP].dport):

				if (pkt[IP].ttl != prevPkt[IP].ttl or
					pkt[Ether].src != prevPkt[Ether].src or
					not intersection(pkt[DNS].ans, prevPkt[DNS].ans)):
					print_packets(pkt, prevPkt)

				data.append(pkt)

		else:
			data.append(pkt)

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
if args.i is None:
	sniff(filter=bpf, prn=detect)
else:
	sniff(filter=bpf, iface=args.i, prn=detect)