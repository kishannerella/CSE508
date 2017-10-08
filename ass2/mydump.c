/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 * 
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and 
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 * 
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 */

#define APP_NAME      "mydump"
#define APP_DESC      "Sniffer example using libpcap"
#define APP_COPYRIGHT   "Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER   "THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define MAX_FILTER_SIZE 1000

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN   6

#define ICMP_HEADER_SIZE 8

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* UDP header*/
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_len;                 /* total length */
        u_short uh_sum;                 /* checksum */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_banner(void);

void print_app_usage(void);

void print_app_banner(void)
{

   printf("%s - %s\n", APP_NAME, APP_DESC);
   printf("%s\n", APP_COPYRIGHT);
   printf("%s\n", APP_DISCLAIMER);
   printf("\n");

   return;
}

void
print_app_usage(void)
{

   printf("Usage: %s [-i <interface>] [-r <filename>] [-s <string>] [BPF filter]\n", APP_NAME);
   printf("-i or -r is mandatory\n");
   printf("\n");
   return;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

   int i;
   int gap;
   const u_char *ch;

   /* offset */
   printf("%05d   ", offset);
   
   /* hex */
   ch = payload;
   for(i = 0; i < len; i++) {
      printf("%02x ", *ch);
      ch++;
      /* print extra space after 8th byte for visual aid */
      if (i == 7)
         printf(" ");
   }
   /* print space to handle line less than 8 bytes */
   if (len < 8)
      printf(" ");
   
   /* fill hex gap with spaces if not full line */
   if (len < 16) {
      gap = 16 - len;
      for (i = 0; i < gap; i++) {
         printf("   ");
      }
   }
   printf("   ");
   
   /* ascii (if printable) */
   ch = payload;
   for(i = 0; i < len; i++) {
      if (isprint(*ch))
         printf("%c", *ch);
      else
         printf(".");
      ch++;
   }

   printf("\n");

   return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

   int len_rem = len;
   int line_width = 16;         /* number of bytes per line */
   int line_len;
   int offset = 0;               /* zero-based offset counter */
   const u_char *ch = payload;

   if (len <= 0)
      return;

   /* data fits on one line */
   if (len <= line_width) {
      print_hex_ascii_line(ch, len, offset);
      return;
   }

   /* data spans multiple lines */
   for ( ;; ) {
      /* compute current line length */
      line_len = line_width % len_rem;
      /* print line */
      print_hex_ascii_line(ch, line_len, offset);
      /* compute total remaining */
      len_rem = len_rem - line_len;
      /* shift pointer to remaining bytes to print */
      ch = ch + line_len;
      /* add offset */
      offset = offset + line_width;
      /* check if we have line width chars or less */
      if (len_rem <= line_width) {
         /* print last line and get out */
         print_hex_ascii_line(ch, len_rem, offset);
         break;
      }
   }

   return;
}

/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

   static int count = 1;                   /* packet counter */
   
   /* declare pointers to packet headers */
   struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
   struct sniff_ip *ip;              /* The IP header */
   struct sniff_tcp *tcp;            /* The TCP header */
   struct sniff_udp *udp;            /* The UDP header */
   char *payload;                    /* Packet payload */

   int size_ip;
   int size_tcp;
   int size_udp;
   int size_payload;
   u_char* m;
 
   //printf("\nPacket number %d:\n", count);
   count++;
   
   /* define ethernet header */
   ethernet = (struct sniff_ethernet*)(packet);
   
   /* define/compute ip header offset */
   ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
   size_ip = IP_HL(ip)*4;
   if (size_ip < 20) {
      printf("   * Invalid IP header length: %u bytes\n", size_ip);
      return;
   }

   /* print source and destination IP addresses */
   
   /* determine protocol */   
   switch(ip->ip_p) {
      case IPPROTO_TCP:
         //printf("   Protocol: TCP\n");
         break;
      case IPPROTO_UDP:
         //printf("   Protocol: UDP\n");
         break;
      case IPPROTO_ICMP:
         //printf("   Protocol: ICMP\n");
         break;
      case IPPROTO_IP:
         printf("   Protocol: IP\n");
         return;
      default:
         printf("   Protocol: unknown\n");
         return;
   }
   
   /*
    *  OK, this packet is TCP.
    */
  
   /*
    2016-02-16 15:04:13.064632 D0:C7:89:A9:C7:40 -> 00:06:5B:FE:42:1A type 0x800 len 74
192.168.0.1:2365 -> 192.168.1.2:80 TCP
    */ 
   /* define/compute tcp header offset */

  
   m = ethernet->ether_shost; 
   printf("%02x:%02x:%02x:%02x:%02x:%02x -> ", m[0], m[1], m[2], m[3], m[4], m[5]);
   m = ethernet->ether_dhost; 
   printf("%02x:%02x:%02x:%02x:%02x:%02x ", m[0], m[1], m[2], m[3], m[4], m[5]);
   printf("type 0x%x ", ntohs(ethernet->ether_type));
   printf("len %u ", ntohs(ip->ip_len));

   if (ip->ip_p == IPPROTO_TCP){
      tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
      printf("%s:%d TCP\n", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
   }else if (ip->ip_p == IPPROTO_UDP){
      udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
      size_udp = sizeof(struct sniff_udp);
      printf("%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
      printf("%s:%d UDP\n", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
      size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
   }else if (ip->ip_p == IPPROTO_ICMP){
      printf("%s -> ", inet_ntoa(ip->ip_src));
      printf("%s ICMP\n", inet_ntoa(ip->ip_dst));
      payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + ICMP_HEADER_SIZE);
      size_payload = ntohs(ip->ip_len) - (size_ip + ICMP_HEADER_SIZE);
   }
   
   /* define/compute tcp payload (segment) offset */
   
   /* compute tcp payload (segment) size */
   
   /*
    * Print payload data; it might be binary, so don't just
    * treat it as a string.
    */
   if (size_payload > 0) {
      //printf("   Payload (%d bytes):\n", size_payload);
      print_payload(payload, size_payload);
   }

   return;
}

int main(int argc, char **argv)
{

   char *dev = NULL;         /* capture device name */
   char errbuf[PCAP_ERRBUF_SIZE];      /* error buffer */
   pcap_t *handle;            /* packet capture handle */

   char filter_exp[MAX_FILTER_SIZE] = "";        /* filter expression [3] */
   struct bpf_program fp;         /* compiled filter program (expression) */
   bpf_u_int32 mask;         /* subnet mask */
   bpf_u_int32 net;         /* ip */
   int num_packets = 10;         /* number of packets to capture */

   int interface_flag = 0;
   int file_flag = 0;
   int search_flag = 0;
   char* file_name;
   char* search_string;
   int opt;
   int i, filter_pos;   
   //print_app_banner();

   while ((opt = getopt(argc, argv, "i:r:s:")) != -1){
      switch (opt){
         case 'i':
            interface_flag = 1;
            dev = optarg;
            break;
         case 'r':
            file_flag = 1;
            file_name = optarg;
            break;
         case 's':
            search_flag = 1;
            search_string = optarg;
            break;
         default:
            fprintf(stderr, "error: unrecognized command-line options\n\n");
            print_app_usage();
            exit(EXIT_FAILURE);
            
      }
   }

   if (file_flag && interface_flag){
      fprintf(stderr, "error: invalid combination of -i and -r options\n\n");
      exit(EXIT_FAILURE);
   }
   
   if (!file_flag && !interface_flag){
      fprintf(stderr, "error: one of -i or -r options MUST be provided\n\n");
      exit(EXIT_FAILURE);
   }
   for (i = optind;i < argc;i++){
      strcat(filter_exp, " ");
      strcat(filter_exp, argv[i]);
   }

   /* get network number and mask associated with capture device */
   if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
      fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
          dev, errbuf);
      net = 0;
      mask = 0;
   }

   /* print capture info */
   printf("Device: %s\n", dev);
   printf("Number of packets: %d\n", num_packets);
   printf("Filter expression: %s\n", filter_exp);

   /* open capture device */
   handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
   if (handle == NULL) {
      fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
      exit(EXIT_FAILURE);
   }

   /* make sure we're capturing on an Ethernet device [2] */
   if (pcap_datalink(handle) != DLT_EN10MB) {
      fprintf(stderr, "%s is not an Ethernet\n", dev);
      exit(EXIT_FAILURE);
   }

   /* compile the filter expression */
   if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
      fprintf(stderr, "Couldn't parse filter %s: %s\n",
          filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
   }

   /* apply the compiled filter */
   if (pcap_setfilter(handle, &fp) == -1) {
      fprintf(stderr, "Couldn't install filter %s: %s\n",
          filter_exp, pcap_geterr(handle));
      exit(EXIT_FAILURE);
   }

   /* now we can set our callback function */
   pcap_loop(handle, num_packets, got_packet, NULL);

   /* cleanup */
   pcap_freecode(&fp);
   pcap_close(handle);

   printf("\nCapture complete.\n");

   return 0;
}

