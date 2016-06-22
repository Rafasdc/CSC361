#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>

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

void print_connections();
void print_general();
void print_complete();



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

      packet_counter++;

    }
    pcap_close(handle);


  printf("\nA) Total number of connections: %d\n", packet_counter);
  printf("___________________________\n");
  print_connections();
  print_general();
  print_complete();
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
