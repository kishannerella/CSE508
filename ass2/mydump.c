/*
 * mydump.c
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

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
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

#define ETHER_TYPE_IP   0x0800

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

void print_app_usage(void);

void print_app_usage(void)
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
void print_payload(const u_char *payload, int len)
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

void get_time_str(const struct pcap_pkthdr *header, char* str)
{
   const time_t* secs = &(header->ts.tv_sec);
   struct tm* t = localtime(secs);

   /* Print time in the required format */
   sprintf(str, "%4d-%02d-%02d %02d:%02d:%02d.%06d ",(1900 + t->tm_year), (t->tm_mon + 1), 
           t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, (int)header->ts.tv_usec); 

}

void get_ether_str(struct sniff_ethernet *ethernet, bpf_u_int32 pktlen, char* str)
{
   u_char* m;
   char temp[1000];

   *str = '\0';
   /* Print source and destination MAC address */ 
   m = ethernet->ether_shost; 
   sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x -> ", 
           m[0], m[1], m[2], m[3], m[4], m[5]);
   strcat(str, temp);
   m = ethernet->ether_dhost; 
   sprintf(temp, "%02x:%02x:%02x:%02x:%02x:%02x ", 
           m[0], m[1], m[2], m[3], m[4], m[5]);
   strcat(str, temp);
   sprintf(temp, "type 0x%x ", ntohs(ethernet->ether_type));
   strcat(str, temp);
   sprintf(temp, "len %u ", pktlen);
   strcat(str, temp);

}

/*
 * dissect/print packet
 */
void got_packet(u_char *pattern, const struct pcap_pkthdr *header, const u_char *packet)
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
   int i;
   char pktinfo[1000] = "";
   char temp[100000] = "";
   char *ch;

   /* FORMAT -
    * 2016-02-16 15:04:13.064632 D0:C7:89:A9:C7:40 -> 00:06:5B:FE:42:1A 
    * type 0x800 len 74 192.168.0.1:2365 -> 192.168.1.2:80 TCP
    */

   count++;
   get_time_str(header, temp);
   strcat(pktinfo, temp);

   /* define ethernet header */
   ethernet = (struct sniff_ethernet*)(packet);

   get_ether_str(ethernet, header->len, temp);
   strcat(pktinfo, temp);

   /* If this is not an IP packet, print everything after ethernet header */
   if (ntohs(ethernet->ether_type) != ETHER_TYPE_IP) {
      payload = (u_char *)(packet + SIZE_ETHERNET);
      size_payload = header->len - SIZE_ETHERNET;
   }
   else{
      /* define/compute ip header offset */
      ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
      size_ip = IP_HL(ip)*4;
      
  
      if (ip->ip_p == IPPROTO_TCP){
         tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
         size_tcp = TH_OFF(tcp)*4;

         payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
         size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

         sprintf(temp, "%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
         strcat(pktinfo, temp);
         sprintf(temp, "%s:%d TCP", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
         strcat(pktinfo, temp);
      }else if (ip->ip_p == IPPROTO_UDP){
         udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
         size_udp = sizeof(struct sniff_udp);

         payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
         size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

         sprintf(temp, "%s:%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
         strcat(pktinfo, temp);
         sprintf(temp, "%s:%d UDP", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
         strcat(pktinfo, temp);
      }else if (ip->ip_p == IPPROTO_ICMP){
         payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + ICMP_HEADER_SIZE);
         size_payload = ntohs(ip->ip_len) - (size_ip + ICMP_HEADER_SIZE);

         sprintf(temp, "%s -> ", inet_ntoa(ip->ip_src));
         strcat(pktinfo, temp);
         sprintf(temp, "%s ICMP", inet_ntoa(ip->ip_dst));
         strcat(pktinfo, temp);
      }else{
         payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
         size_payload = ntohs(ip->ip_len) - (size_ip);

         sprintf(temp, "%s -> ", inet_ntoa(ip->ip_src));
         strcat(pktinfo, temp);
         sprintf(temp, "%s OTHER", inet_ntoa(ip->ip_dst));
         strcat(pktinfo, temp);
      }
   }

   /* Search for the pattern in the payload and skip the packet if present */
   if (pattern){
      ch = payload;
      for(i = 0; i < size_payload; i++) {
         if (isprint(*ch))
            temp[i] = *ch;
         else
            temp[i] = '.';
         ch++;
      }
      temp[i] = '\0';

      if (!strstr(temp, pattern))
         return;
   }

   /*
    * Print Packet info and payload data; 
    */
   puts(pktinfo);
   if (size_payload > 0) {
     print_payload(payload, size_payload);
   }
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

   int interface_flag = 0;
   int file_flag = 0;
   int search_flag = 0;
   char* file_name;
   char* search_string = NULL;
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

   /* open capture device */
   if (file_flag)
      handle = pcap_open_offline(file_name, errbuf);
   else
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
   pcap_loop(handle, -1, got_packet, search_string);

   /* cleanup */
   pcap_freecode(&fp);
   pcap_close(handle);

   printf("\nCapture complete.\n");

   return 0;
}

