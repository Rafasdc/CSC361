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


#define MAX_STR_LEN 100
#define MAX_HOPS 1000



//parses the packet
int parse_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS],
 int protocols [MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]);


//global variable for easier printing and manipulation

int main(int argc, char **argv)
{
  char err_buff [PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  const u_char *packet;
  struct router routers [MAX_HOPS];
  struct outgoing times [MAX_HOPS];
  int protocols [MAX_STR_LEN];

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

   total_connections = 0;
   while (packet = pcap_next(handle,&header)) {
     parse_packet(packet,header.caplen,routers,protocols,header.ts,times);
    }
    pcap_close(handle);


  return 0;
}







int parse_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS],
 int protocols [MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]){
  
  struct ip *ip; //ip header
  unsigned int IP_header_length; //ip header length

  //Skip over Ethernet header
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);


  if (capture_len < sizeof(struct ip)){
    printf("IP header too short");
    return -1;
  }

  //get ip header size and ip header
  ip = (struct ip*) packet;
  IP_header_length = ip->ip_hl * 4;

  
  //check ip header size
  if (capture_len < IP_header_length){
    printf("IP header with options too short");
    return -1;
  }



  
  //SKIP IP HEADER
  packet += IP_header_length;
  capture_len -= IP_header_length;

  /*
  if (analyze_packet (ip,packet,routers,protocols,ts,times){
    return 1;
  })
  */

  return 0;

}




/*
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
  /*
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
*/
