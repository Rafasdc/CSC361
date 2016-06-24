#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>

#include "headers.h"



void print_connections();
void print_general();
void print_complete();

void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
void check_connection(struct ip *ip, struct TCP_hdr *tcp, struct timeval ts, const char *payload,unsigned int capture_len);

struct connection connections[MAX_NUM_CONNECTION];
int total_connections = 0;
struct timeval first_time;
int min_packets, mean_packets, max_packets = 0;
int mean_window, max_window = 0;
int min_window = -1;
double min_duration, mean_duration, max_duration = 0;

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

   //TODO filter out HTTP packets and other packets use only TCP

   if (handle == NULL) {
     fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
     return(2);
   }

   total_connections = 0;
   while (packet = pcap_next(handle,&header)) {
     parse_packet(packet,header.ts,header.caplen);
      packet_counter++;

    }
    pcap_close(handle);


  printf("\nA) Total number of connections: %d\n", total_connections);
  printf("___________________________\n");
  print_connections();
  print_general();

  print_complete();
  return 0;
}

void print_connections(){
  time_t initial_time;
  initial_time = first_time.tv_sec;
  double init_time = (double)initial_time;
  init_time += (1.0/1000000)*first_time.tv_usec;
  printf("%f\n",init_time);
  printf("\nB) Connections' details\n\n");
  //while still connection info to print
  int i = 0;
  for (; i < total_connections; i++){
    printf("Connection %d:\nSource Address: %s\nDestination Address: %s\nSource Port: %d\n", i+1, connections[i].ip_src,connections[i].ip_dst, connections[i].port_src);
    printf("Destination Port: %d\n", connections[i].port_dst);
    int syn = connections[i].syn_count;
    int fin = connections[i].fin_count;
    int rst = connections[i].rst_count;
    if (connections[i].rst_count > 0){
    printf("Status: R\n");
    }
    else if (syn == 1 && fin == 0){
      printf("Status: S1F0\n");
    } else if (syn ==2 && fin == 0){
      printf("Status: S2F0\n");
    }else if (syn == 1 && fin == 1){
      printf("Status: S1F1\n");
    } else if (syn ==2 && fin ==1){
      printf("Status: S2F1\n");
    } else if (syn == 2 && fin ==2){
      printf("Status: S2F2\n");
    } else if (syn == 0 && fin ==1){
      printf("Status: S0F1\n");
    } else if (syn == 0 && fin == 2){
      printf("Status: S0F2\n");
    }
    //if complete printf

      time_t start_time = connections[i].starting_time.tv_sec;
      double startt = (double)start_time;
      startt += (1.0/1000000)*connections[i].starting_time.tv_usec;
      startt -= init_time;


      time_t end_time = connections[i].ending_time.tv_sec;
      double endt = (double)end_time;
      endt+=(1.0/1000000)*connections[i].ending_time.tv_usec;
      endt -= init_time;


      double duration = endt-startt;
      mean_duration += duration;
      if (duration > max_duration){
        max_duration = duration;
      }
      if (min_duration == 0){
        min_duration = duration;
      } else if (duration < min_duration) {
        min_duration = duration;
      }

      int total_packets = connections[i].num_total_packets;
      mean_packets += total_packets;
      if (total_packets > max_packets){
        max_packets = total_packets;
      }
      if (min_packets == 0){
        min_packets = total_packets;
      } else if (total_packets < min_packets){
        min_packets = total_packets;
      }

      if (connections[i].max_win_size > max_window){
        max_window = connections[i].max_win_size;
      }
      if (min_window == -1){
        min_window = connections[i].min_win_size;
      } else if (connections[i].min_win_size < min_window){
        min_window = connections[i].min_win_size;
      }

      mean_window += connections[i].sum_win_size;


    if (connections[i].syn_count > 0 && connections[i].fin_count>0){
      printf("Start Time: %f\n",startt);
      printf("End Time: %f\n",endt);
      printf("Duration: %f\n",duration);
      printf("Number of packets sent from Source to Destination: %d \n",connections[i].num_packet_src);
      printf("Number of Packets sent from Destination to Source: %d\n",connections[i].num_packet_dst);
      printf("Total number of packets: %d \n",connections[i].num_total_packets);
      printf("Number of data bytes sent from Source to Destination: %d\n",connections[i].cur_data_len_src);
      printf("Number of data bytes sent from Destination to Source: %d\n",connections[i].cur_data_len_dst);
      printf("Total number of data bytes: %d\n",connections[i].cur_total_data_len);
      //end of connection
    }
    printf("END\n++++++++++++++++++++++++++++++++++++++\n");
  }
}

void print_general(){
  int i = 0;
  int complete_tcp = 0;
  int reset_tcp = 0;
  int still_open = 0;
  for(;i< total_connections; i++){
    if(connections[i].rst_count>0){
      reset_tcp++;
    }
    if (connections[i].syn_count > 0 && connections[i].fin_count>0){
      complete_tcp++;
    } else {
      still_open++;
    }
  }
  printf("C) General\n\n");
  printf("Total number of complete TCP connections: %d\n",complete_tcp);
  printf("Number of reset TCP connections: %d\n",reset_tcp);
  printf("Number of TCP connections that were still open when the trace capture ended: %d\n", still_open);
  printf("\n______________________________________________\n");
}

void print_complete(){
  printf("D) Complete TCP connections\n");
  printf("Minimum time durations: %f\n",min_duration);
  printf("Mean time durations: %f\n",mean_duration/total_connections);
  printf("Maximum time durations: %f\n\n",max_duration);
  printf("Minimum RTT values including both send/received:\n");
  printf("Mean RTT values including both send/received: \n");
  printf("Maximum RTT values including both send/received: \n\n");
  printf("Minimum number of packets including both send/received: %d\n",min_packets);
  printf("Mean number of packets including both send/received: %d\n", mean_packets/total_connections);
  printf("Maximum number of packets including both send/received: %d\n\n",max_packets);
  printf("Minimum received window size including both send/received: %d\n", min_window);
  printf("Mean received window size including both send/received: %d\n", mean_window/total_connections);
  printf("Maximum received window size including both send/received: %d\n\n",max_window);
  printf("_____________________________________________\n");
}

void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len){
  struct ip *ip; //ip header
  struct TCP_hdr *tcp; //tcp header
  unsigned int IP_header_length; //ip header length
  const char *payload;
  unsigned int capture_len_original = capture_len;

  //Skip over Ethernet header
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);

  if (capture_len < sizeof(struct ip)){
    printf("IP header too short");
    return;
  }

  //get ip header size and ip header
  ip = (struct ip*) packet;
  IP_header_length = ip->ip_hl * 4;

  //check ip header size
  if (capture_len < IP_header_length){
    printf("IP header with options too short");
    return;
  }

  //get to the TCP header
  packet += IP_header_length;
  capture_len -= IP_header_length;

  tcp = (struct TCP_hdr*) packet;

  if (capture_len < sizeof(struct TCP_hdr)){
    printf("TCP Header too short");
    return;
  }

  //get the payload
  packet += TH_OFF(tcp)*4;
  payload = (u_char *)packet;


  check_connection(ip,tcp,ts,payload,capture_len_original);
  //char *addr = inet_ntoa(ip->ip_src);
  //printf("src addr=%s dst addr = %s,src_port=%d dst_port=%d\n",addr,inet_ntoa(ip->ip_dst),ntohs(tcp->th_sport),ntohs(tcp->th_dport));

}

//TODO function to handle num_packet from source and num_packet from dst and also for bytes
//TODO function to count syn, fin and rst and add them to connection
//TODO RTT function

/*
 To obtain the RTT times for a complete TCP connection, you can take this approach:
  (1) First RTT: The time when the first SYN is sent to the time when the first SYN+ACK is received.
  (you need to compare the seq number and the ack number to find the match.
  (2) Second RTT: the time when the first DATA/ACK is sent to the time when the first ACK/DATA is received,
  (you need to compare the seq number and the ack number to find the match).
  (3) Third RTT: the time when the next DATA/ACK is sent to the time when the next ACK/DATA is received.
  (you need to compare the seq number and the ack number to find the match).......
  The last RTT: the last match between FIN and ACK.
*/

void check_connection(struct ip *ip, struct TCP_hdr *tcp, struct timeval ts, const char *payload,unsigned int capture_len){
  int i = 0;
  int match = 0;
  if (total_connections == 0){
    strcpy(connections[total_connections].ip_src, inet_ntoa(ip->ip_src));
    strcpy(connections[total_connections].ip_dst, inet_ntoa(ip->ip_dst));
    connections[total_connections].port_src = ntohs(tcp->th_sport);
    connections[total_connections].port_dst = ntohs(tcp->th_dport);
    connections[total_connections].is_set = 1;
    first_time = ts;
    connections[total_connections].starting_time = ts;
    //printf("flag is %d\n",tcp->th_flags);
    if (tcp->th_flags & TH_FIN){
      connections[total_connections].fin_count+=1;
    } else if (tcp->th_flags & TH_SYN){
      connections[total_connections].syn_count+=1;
    } else if (tcp->th_flags & TH_RST){
      connections[total_connections].rst_count+=1;
    }
    //TODO add the rest of fields
    connections[total_connections].num_packet_src++;
    connections[total_connections].num_total_packets++;
    connections[total_connections].cur_data_len_src += capture_len;
    connections[total_connections].cur_total_data_len += capture_len;
    connections[total_connections].max_win_size = tcp->th_win;
    connections[total_connections].min_win_size = tcp->th_win;
    connections[total_connections].sum_win_size += tcp->th_win;
    total_connections++;
    return;
  }
  for (; i <= total_connections; i++){
    if ((connections[i].port_src == ntohs(tcp->th_sport) && connections[i].port_dst == ntohs(tcp->th_dport)
    && !strcmp(connections[i].ip_dst,inet_ntoa(ip->ip_dst)) && !strcmp(connections[i].ip_src,inet_ntoa(ip->ip_src))) ||
    (connections[i].port_src == ntohs(tcp->th_dport) && connections[i].port_dst == ntohs(tcp->th_sport)
    && !strcmp(connections[i].ip_dst,inet_ntoa(ip->ip_src)) && !strcmp(connections[i].ip_src,inet_ntoa(ip->ip_dst)))){
      match = 1;
      //the matched connection is at i, this is the one we are going to modify if syn, fin, rst and add packets to
      break;
    }
  }
  if (match == 0){
  //no match
  strcpy(connections[total_connections].ip_src, inet_ntoa(ip->ip_src));
  strcpy(connections[total_connections].ip_dst, inet_ntoa(ip->ip_dst));
  connections[total_connections].port_src = ntohs(tcp->th_sport);
  connections[total_connections].port_dst = ntohs(tcp->th_dport);
  connections[total_connections].is_set = 1;
  connections[total_connections].starting_time = ts;

  if (tcp->th_flags & TH_FIN){
    connections[total_connections].fin_count+=1;
  } else if (tcp->th_flags & TH_SYN){
    connections[total_connections].syn_count+=1;
  } else if (tcp->th_flags & TH_RST){
    connections[total_connections].rst_count+=1;
  }
  connections[total_connections].num_packet_src++;
  connections[total_connections].num_total_packets++;
  connections[total_connections].cur_data_len_src += capture_len;
  connections[total_connections].cur_total_data_len += capture_len;
  connections[total_connections].max_win_size = tcp->th_win;
  connections[total_connections].min_win_size = tcp->th_win;
  connections[total_connections].sum_win_size += tcp->th_win;
  total_connections++;
} else if (match == 1){
  //match is at i
  //we have a match and have to handle modify the connection to which packet matched

  if (tcp->th_flags & TH_FIN){
    //printf("in RST\n");
    connections[i].fin_count+=1;
  } else if (tcp->th_flags & TH_SYN){
    //printf("in SYN\n");
    connections[i].syn_count+=1;
  } else if (tcp->th_flags & TH_RST){
    //printf("in RST\n");
    connections[i].rst_count+=1;
  }
  //update endtime everytime a match is found this will be useful later
  connections[i].ending_time = ts;

  //handle packets and data sent
  if(connections[i].port_src == ntohs(tcp->th_dport) && connections[i].port_dst == ntohs(tcp->th_sport)
  && !strcmp(connections[i].ip_dst,inet_ntoa(ip->ip_src)) && !strcmp(connections[i].ip_src,inet_ntoa(ip->ip_dst))){
    connections[i].num_packet_dst++;
    connections[i].num_total_packets++;
    connections[i].cur_data_len_dst += capture_len;
    connections[i].cur_total_data_len += capture_len;
  } else {
    connections[i].num_packet_src++;
    connections[i].num_total_packets++;
    connections[i].cur_data_len_src += capture_len;
    connections[i].cur_total_data_len += capture_len;
  }
  if (tcp->th_win > connections[i].max_win_size){
    connections[i].max_win_size = tcp->th_win;
  }
  if (tcp->th_win < connections[i].min_win_size){
    connections[i].min_win_size = tcp->th_win;
  }
  connections[i].sum_win_size += tcp->th_win;


}




}
