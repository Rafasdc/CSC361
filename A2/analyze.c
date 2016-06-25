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


//handles the output and prints the connections
void print_connections();
//creates and prints the required general information
void print_general();
//uses information from the previos two functions to print the data pertaining to the
//complete TCP connections
void print_complete();

//parses the packet
void parse_packet(const unsigned char *packet, struct timeval ts, unsigned int capture_len);
//check the packet and add its info to the correspoding connection
void check_connection(struct ip *ip, struct TCP_hdr *tcp, struct timeval ts, const char *payload,unsigned int capture_len);
//calculates rtt
void calculate_rtt();

//global variable for easier printing and manipulation
struct connection connections[MAX_NUM_CONNECTION];
int total_connections = 0;
struct timeval first_time;
int min_packets, mean_packets, max_packets = 0;
int mean_window, max_window, total_windows = 0;
int min_window = -1;
double min_duration, mean_duration, max_duration = 0;
double min_rtt = -1;
double max_rtt, mean_rtt = 0;
int complete_tcp = 0;
int reset_tcp = 0;
int still_open = 0;
int rtt_total = 0;

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

   struct bpf_program fp;
   if (pcap_compile(handle, &fp, "tcp", 0, 0) == -1) {
       fprintf(stderr, "Couldn't compile filter: %s\n", pcap_geterr(handle));
       return(2);
   }
   if (pcap_setfilter(handle, &fp) == -1) {
       fprintf(stderr, "Couldn't set filter: %s\n",pcap_geterr(handle));
       return(2);
   }

   total_connections = 0;
   while (packet = pcap_next(handle,&header)) {
     parse_packet(packet,header.ts,header.caplen);
    }
    pcap_close(handle);


  printf("\nA) Total number of connections: %d\n", total_connections);
  printf("___________________________\n");
  print_connections();
  print_general();
  calculate_rtt();
  print_complete();
  return 0;
}

void print_connections(){
  time_t initial_time;
  initial_time = first_time.tv_sec;
  double init_time = (double)initial_time;
  init_time += (1.0/1000000)*first_time.tv_usec;
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
    //check status and prints corresponding
    //read README for explanation of R handling
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

    if (connections[i].syn_count > 0 && connections[i].fin_count>0){ //check connection complete

      //get the start time
      time_t start_time = connections[i].starting_time.tv_sec;
      double startt = (double)start_time;
      startt += (1.0/1000000)*connections[i].starting_time.tv_usec;
      startt -= init_time;

      //get the endtime
      time_t end_time = connections[i].ending_time.tv_sec;
      double endt = (double)end_time;
      endt+=(1.0/1000000)*connections[i].ending_time.tv_usec;
      endt -= init_time;

      //get the duration of the connection
      double duration = endt-startt;
      mean_duration += duration;
      if (duration > max_duration){
        max_duration = duration;
      }

      //min, max and mean handlers above
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
      total_windows += connections[i].num_total_packets;
      mean_window += connections[i].sum_win_size;

      //start printing
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
  //calculate the reset, complete and open connections
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
  //prints the above info in required format
  printf("C) General\n\n");
  printf("Total number of complete TCP connections: %d\n",complete_tcp);
  printf("Number of reset TCP connections: %d\n",reset_tcp);
  printf("Number of TCP connections that were still open when the trace capture ended: %d\n", still_open);
  printf("\n______________________________________________\n");
}

//prints the information of complete TCP connections using all the global variables previosly declared
void print_complete(){
  printf("D) Complete TCP connections\n");
  printf("Minimum time durations: %f\n",min_duration);
  printf("Mean time durations: %f\n",mean_duration/complete_tcp);
  printf("Maximum time durations: %f\n\n",max_duration);
  printf("Minimum RTT values including both send/received: %f\n",min_rtt);
  printf("Mean RTT values including both send/received: %f\n",mean_rtt/rtt_total);
  printf("Maximum RTT values including both send/received: %f\n\n",max_rtt);
  printf("Minimum number of packets including both send/received: %d\n",min_packets);
  printf("Mean number of packets including both send/received: %d\n", mean_packets/complete_tcp);
  printf("Maximum number of packets including both send/received: %d\n\n",max_packets);
  printf("Minimum received window size including both send/received: %d\n", min_window);
  printf("Mean received window size including both send/received: %d\n", mean_window/total_windows);
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

  capture_len -= TH_OFF(tcp)*4;
  //get the payload
  packet += TH_OFF(tcp)*4;
  payload = (u_char *)packet;


  check_connection(ip,tcp,ts,payload,capture_len);
  //char *addr = inet_ntoa(ip->ip_src);
  //printf("src addr=%s dst addr = %s,src_port=%d dst_port=%d\n",addr,inet_ntoa(ip->ip_dst),ntohs(tcp->th_sport),ntohs(tcp->th_dport));

}





void check_connection(struct ip *ip, struct TCP_hdr *tcp, struct timeval ts, const char *payload,unsigned int capture_len){
  int i = 0;
  int match = 0;
  //printf(" Win: %d\n", ntohs(tcp->th_win));
  if (total_connections == 0){
    //printf ("FIRST PACK IN CONN WITH: SEQ is %d and ACK is %d with conn= %d\n ", ntohs(tcp->th_seq), ntohs(tcp->th_ack),total_connections);
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
      connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].starting_time = ts;
      connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].syn_count++;
      connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].first_seq = ntohs(tcp->th_seq);
      connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].looking_syn_ack = 1;
      connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].looking_for = ntohs(tcp->th_seq);
    } else if (tcp->th_flags & TH_RST){
      connections[total_connections].rst_count+=1;
    }
    connections[total_connections].num_packet_src++;
    connections[total_connections].num_total_packets++;
    connections[total_connections].cur_data_len_src += capture_len;
    connections[total_connections].cur_total_data_len += capture_len;
    connections[total_connections].max_win_size = ntohs(tcp->th_win);
    connections[total_connections].min_win_size = ntohs(tcp->th_win);
    connections[total_connections].sum_win_size += ntohs(tcp->th_win);
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
    connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].starting_time = ts;
    connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].syn_count++;
    connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].looking_syn_ack = 1;
    connections[total_connections].rtt_array[connections[total_connections].rtt_array_len].looking_for = ntohs(tcp->th_seq);
  } else if (tcp->th_flags & TH_RST){
    connections[total_connections].rst_count+=1;
  }
  connections[total_connections].num_packet_src++;
  connections[total_connections].num_total_packets++;
  connections[total_connections].cur_data_len_src += capture_len;
  connections[total_connections].cur_total_data_len += capture_len;
  connections[total_connections].max_win_size = ntohs(tcp->th_win);
  connections[total_connections].min_win_size = ntohs(tcp->th_win);
  connections[total_connections].sum_win_size += ntohs(tcp->th_win);
  //printf ("FIRST PACK IN CONN WITH: SEQ is %d and ACK is %d with conn= %d\n ", ntohs(tcp->th_seq), ntohs(tcp->th_ack),total_connections);
  total_connections++;
} else if (match == 1){
  //match is at i
  //we have a match and have to handle modify the connection to which packet matched
  int first = connections[i].rtt_array[connections[i].rtt_array_len].first;
  //if its the first package we are going to look for a match for RTT then we look for ack matching seq
  if (first == 1){
    connections[i].rtt_array[connections[i].rtt_array_len].starting_time = ts;
    connections[i].rtt_array[connections[i].rtt_array_len].first = 0;
    connections[i].rtt_array[connections[i].rtt_array_len].looking_for = ntohs(tcp->th_seq);
    connections[i].rtt_array[connections[i].rtt_array_len].looking_for_ack = 1;
    connections[i].rtt_array[connections[i].rtt_array_len].looking_for_seq = 0;
  }
  int connection_first_seq = connections[i].rtt_array[0].first_seq;
  if (tcp->th_flags & TH_FIN){
    connections[i].fin_count+=1;
    connections[i].rtt_array[connections[i].rtt_array_len].starting_time = ts;
    connections[i].rtt_array[connections[i].rtt_array_len].fin = 1;
  } else if (tcp->th_flags & TH_SYN){
    //printf("in SYN\n");
    connections[i].syn_count+=1;
    if (tcp->th_flags & TH_ACK ){
      //printf("SYN and ACK\n");
      //if SYN and ACK then we check for matching ack with seq, if there is then we found the first RTT
      if (connections[i].rtt_array[connections[i].rtt_array_len].looking_for == (ntohs(tcp->th_ack)) && connections[i].rtt_array[connections[i].rtt_array_len].looking_syn_ack == 1){
        //printf("found matching ACK = %d with initial SEQ\n ",ntohs(tcp->th_ack));
          connections[i].rtt_array[connections[i].rtt_array_len].ending_time = ts;
          connections[i].rtt_array[connections[i].rtt_array_len].syn_count++;
          connections[i].rtt_array[connections[i].rtt_array_len].looking_syn_ack = 0;
          connections[i].rtt_array_len++;
          connections[i].rtt_array[connections[i].rtt_array_len].looking_for = ntohs(tcp->th_ack);
          connections[i].rtt_array[connections[i].rtt_array_len].starting_time = ts;
          connections[i].rtt_array[connections[i].rtt_array_len].looking_for_seq = 1;
          //printf("ACK in HERE IS %d with i = %d\n",connections[i].rtt_array[connections[i].rtt_array_len].ack, i);
          //printf("looking for %d in SEQ\n", ntohs(tcp->th_ack));
      }
    }
  } else if (tcp->th_flags & TH_RST){
    //printf("in RST\n");
    connections[i].rst_count+=1;
  }

  if (tcp->th_flags & TH_ACK){
    //printf ("SEQ is %d and ACK is %d with i = %d\n ", ntohs(tcp->th_seq), ntohs(tcp->th_ack),i);
    if(connections[i].rtt_array[connections[i].rtt_array_len].looking_for_seq == 1){
      //printf("Looking for ACK %d found SEQ %d\n", connections[i].rtt_array[connections[i].rtt_array_len].ack,ntohs(tcp->th_seq));
      if (connections[i].rtt_array[connections[i].rtt_array_len].looking_for == ntohs(tcp->th_seq)){
        //printf("found match with SEQ %d, with above SEQ\n",ntohs(tcp->th_seq));
        connections[i].rtt_array[connections[i].rtt_array_len].ending_time = ts;
        connections[i].rtt_array_len++;
        connections[i].rtt_array[connections[i].rtt_array_len].looking_for = ntohs(tcp->th_seq);
        connections[i].rtt_array[connections[i].rtt_array_len].first = 1;
        connections[i].rtt_array[connections[i].rtt_array_len].looking_for_ack = 1; //reverse it (useful for first few RTT)
      }
    }else if (connections[i].rtt_array[connections[i].rtt_array_len].looking_for_ack == 1){
      //printf("Looking for SEQ %d found ACK %d\n", connections[i].rtt_array[connections[i].rtt_array_len].seq,ntohs(tcp->th_ack));
      if (connections[i].rtt_array[connections[i].rtt_array_len].looking_for == ntohs(tcp->th_ack)){
        //printf("found match with ACK %d, with above ACK\n",ntohs(tcp->th_ack));
        connections[i].rtt_array[connections[i].rtt_array_len].ending_time = ts;
        connections[i].rtt_array_len++;
        connections[i].rtt_array[connections[i].rtt_array_len].looking_for = ntohs(tcp->th_ack);
        connections[i].rtt_array[connections[i].rtt_array_len].first = 1;
        connections[i].rtt_array[connections[i].rtt_array_len].looking_for_seq = 1; //reverse it (useful for first few RTT)
      }
    }
  }
  //update endtime everytime a match is found this will be useful later for duration and start end
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
  if (ntohs(tcp->th_win) > connections[i].max_win_size){
    connections[i].max_win_size = ntohs(tcp->th_win);
  }
  if (ntohs(tcp->th_win) < connections[i].min_win_size){
    connections[i].min_win_size = ntohs(tcp->th_win);
  }
  connections[i].sum_win_size += ntohs(tcp->th_win);


  }

}
//TODO fix RTT function and Window size

/*
 To obtain the RTT times for a complete TCP connection, you can take this approach:
  (1) First RTT: The time when the first SYN is sent to the time when the first SYN+ACK is received.
  (you need to compare the seq number and the ack number to find the match.
  (2) Second RTT: the time when the first DATA/ACK is sent to the time when the first ACK/DATA is received,
  (you need to compare the seq number and the ack number to find the match).
  (3) Third RTT: the time when the next DATA/ACK is sent to the time when the next ACK/DATA is received.
  (you need to compare the seq number and the ack number to find the match).......
  The last RTT: the last match between FIN and ACK.
  This is all done when finding connection pairs
*/
void calculate_rtt(){
  int i = 0;

  time_t initial_time;
  initial_time = first_time.tv_sec;
  double init_time = (double)initial_time;
  init_time += (1.0/1000000)*first_time.tv_usec;
  for (;i<total_connections;i++){
    int j = 0;
    if (connections[i].syn_count > 0 && connections[i].fin_count>0){
      while(j<connections[i].rtt_array_len){
        //calculate rtt for all connections and update min max and add them all to get mean
        time_t start_time = connections[i].rtt_array[j].starting_time.tv_sec;
        double startt = (double)start_time;
        startt += (1.0/1000000)*connections[i].rtt_array[j].starting_time.tv_usec;
        startt -= init_time;
        time_t end_time = connections[i].rtt_array[j].ending_time.tv_sec;
        double endt = (double)end_time;
        endt +=(1.0/1000000)*connections[i].rtt_array[j].ending_time.tv_usec;
        endt -= init_time;
        double duration = endt-startt;
        //printf("%f\n", duration);
        mean_rtt += duration;
        rtt_total++;
        if (duration > max_rtt){
          max_rtt = duration;
        }
        if (min_rtt == -1){
          min_rtt = duration;
        } else if (duration < min_rtt) {
          min_rtt = duration;
        }
        j++;
      }
    }
  }
}
