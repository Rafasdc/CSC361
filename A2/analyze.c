#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>

/*
struct TCP_hdr {
  u_short th_sport;
  u_short th_dport;
  unsigned int th_seq;
  unsigned int th_ack;
  u_char th_offx2;
  #define TH_OFF(th)
}
*/

//void parse_packet(struct timeval ts, )

struct TCP_hdr {
  u_short th_sport;	/* source port */
  u_short th_dport;	/* destination port */
  unsigned int th_seq;		/* sequence number */
  unsigned int th_ack;		/* acknowledgement number */
  u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};


void print_connections();
void print_general();
void print_complete();

void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);

int main(int argc, char **argv)
{
  unsigned int packet_counter=0;
  struct pcap_pkthdr header;
  const u_char *packet;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    exit(1);
  }

   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   handle = pcap_open_offline(argv[1], errbuf);

   if (handle == NULL) {
     fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     return(2);
   }

   while (packet = pcap_next(handle,&header)) {
     parse_packet(packet,header.ts,header.caplen);
      packet_counter++;

    }
    pcap_close(handle);


  printf("\nA) Total number of connections: %d\n", packet_counter);
  printf("___________________________\n");
  //print_connections();
  //print_general();
  //print_complete();
  return 0;
}

void print_connections(){
  printf("\nB) Connections' details\n\n");
  //while still connection info to print
  printf("Connection :\nSource Address:\nDestination Address:\n,Source Port:\n");
  printf("Destinantion Port:\n");
  printf("Status:\n");
  //if complete printf
  printf("Start Time:\n");
  printf("EndTime:\n");
  printf("Duration:\n");
  printf("Number of packets sent from Source to Destination: \n");
  printf("Number of Packets sent from Destination to Source: \n");
  printf("Total number of packets: \n");
  printf("Number of data bytes sent from Source to Destination: \n");
  printf("Number of data bytes sent from Destination to Source: \n");
  printf("Total number of data bytes: \n");
  //end of connection
  printf("END\n++++++++++++++++++++++++++++++++++++++\n");
}

void print_general(){
  printf("C) General\n\n");
  printf("Total number of complete TCP connections: \n");
  printf("Number of reset TCP connections: \n");
  printf("Number of TCP connections that were still open when the trace capture ended\n");
  printf("\n______________________________________________\n");
}

void print_complete(){
  printf("D) Complete TCP connections\n");
  printf("Minimum time durations: \n");
  printf("Mean time durations: \n");
  printf("Maximum time durations: \n\n");
  printf("Minimum RTT values including both send/received:\n");
  printf("Mean RTT values including both send/received: \n");
  printf("Maximum RTT values including both send/received: \n\n");
  printf("Minimum number of packets including both send/received:\n");
  printf("Mean number of packets including both send/received:\n");
  printf("Maximum number of packets including both send/received:\n\n");
  printf("Minimum received window size including both send/received:\n");
  printf("Mean received window size including both send/received:\n");
  printf("Maximum received window size including both send/received:\n\n");
  printf("_____________________________________________\n");
}

void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len){
  struct ip *ip;
  struct TCP_hdr *tcp;
  unsigned int IP_header_length;

  //Skip over Ethernet header
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);

  if (capture_len < sizeof(struct ip)){
    printf("IP header too short");
    exit(-1);
  }

  //get ip header size
  ip = (struct ip*) packet;
  IP_header_length = ip->ip_hl * 4;

  //check ip header size
  if (capture_len < IP_header_length){
    printf("IP header with options too short");
    exit(-1);
  }

  //get to the TCP header
  packet += IP_header_length;
  capture_len -+ IP_header_length;

  tcp = (struct TCP_hdr*) packet;

  if (capture_len < sizeof(struct TCP_hdr)){
    printf("TCP Header too short");
    exit(-1);
  }

  printf("src_port=%d dst_port=%d\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));




}
