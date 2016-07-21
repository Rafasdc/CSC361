#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>


#include "headers.h"


//parses the packet
int parse_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS],
 int protocols [MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]);

void print_info();


//global variable for easier printing and manipulation
char ult_dst[MAX_STR_LEN];
int fragments = 0;
int last_frag;
int list_index = 0;
int first_id;
char src[MAX_STR_LEN];

int main(int argc, char **argv)
{

  pcap_t *handle;
  char err_buff [PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  const unsigned char *packet;

  
  
  struct router routers[MAX_HOPS]; 
  struct outgoing times[MAX_HOPS];
  int protocols [MAX_PROTOCOLS];


  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pcap>\n", argv[0]);
    exit(1);
  }

  handle = pcap_open_offline(argv[1], err_buff);


   if (handle == NULL) {
     fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], err_buff);
     return(2);
   }

   //total_connections = 0;
   while ((packet = pcap_next(handle,&header)) != NULL) {
     if (parse_packet(packet,header.caplen,routers,protocols,header.ts,times)){
      break;
     }
  }
    //pcap_close(handle);

    print_info(routers,times,protocols);


  return 0;
}


void print_info(struct router routers[MAX_HOPS], struct outgoing times[MAX_HOPS], int protocols [MAX_STR_LEN]){
  printf("The IP address of the source node: %s \n", src);
  printf("The IP address of ultimate destination node: %s \n",ult_dst);
  printf("The IP addresses of the intermediate destination nodes: \n");
  int i=0;
  int n = sizeof(routers)/sizeof(routers[0]);
  printf("%d\n", n);
  for(; i< 39; i++){;
    printf("  router %d: %s \n",i, routers[i].src_addr);
  }
  printf("\nThe values in the protocol field of the IP headers:\n");


  int j = 0;
  for(; j < MAX_PROTOCOLS; j++){
    if (protocols[j] == 1){
      printf("%d\n", j);
    }
  }

  printf("\nThe number of fragments created from the original datagram is: %d \n", fragments);
  printf("The offset of the last frament is: %d \n", last_frag);

  //Average RTTs go here.
  printf("The avg RTT between and is: ms, the s.d is: ms");
  
}




int parse_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS],
 int protocols [MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]){
  
  struct ip *ip; //ip header
  unsigned int IP_header_length; //ip header length


  //Skip over Ethernet header
  packet += sizeof(struct ether_header);
  capture_len -= sizeof(struct ether_header);






  //get ip header size and ip header
  ip = (struct ip*) packet;
  IP_header_length = ip->ip_hl * 4;



  //get to the TCP header
  packet += IP_header_length;
  capture_len -= IP_header_length;



  
  if (analyze_packet (ip,packet,routers,protocols,ts,times)){
    //return 1;
  }
  

  return 0; 

}

void add_time(struct ip *ip, int id, struct timeval ts,struct outgoing times[MAX_HOPS] ){
  times[fragments].ip = ip;
  times[fragments].id = id;
  times[fragments].time_sent = ts;
}

void add_to_list(struct router routers[MAX_HOPS],const unsigned char*packet, struct ip *ip, int protocols[MAX_HOPS], struct timeval ts,struct outgoing times[MAX_HOPS]){
      routers[list_index].packet = packet;
      strcpy(routers[list_index].src_addr ,inet_ntoa(ip->ip_src));
      //routers[list_index].protocols = *protocols;
      routers[list_index].time_sent = ts;
      routers[list_index].times = times;
}

int analyze_packet (struct ip *ip, const unsigned char*packet,struct router routers[MAX_HOPS],
  int protocols[MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]){

  //printf("In analyze packet\n");
  struct icmphdr *icmp;
  struct udphdr *udp;
  uint16_t port;
  unsigned short temp,id,offset;
  int mf;
  //printf("ip->ip_p is %d \n",ip->ip_p);

  //get ID of packet
  temp = ip->ip_id;
  id = (temp>>8)|(temp<<8);
  //pakcet if ICMP
  if(ip->ip_p == 1){
    //printf("Creating ICMP\n");
    icmp = (struct icmphdr*) packet; 
    printf("ICMP type is %d \n",icmp->type);
    //add protocol
    protocols[1] = 1;
    //packet timed out
      //printf("ICMP type is %d \n", icmp->type);
    if(icmp->type == 11){
      //add intermiediate router to list
        //printf("%s\n", inet_ntoa(ip->ip_src));
        add_to_list(routers,packet,ip,protocols,ts,times);
        list_index++;
    //first packet sent in trace route 

    } else if ((icmp->type == 8) && (ip->ip_ttl == 1) && (first_id == 0)){
        //set source and ultimate destination address
        strcpy(ult_dst,inet_ntoa(ip->ip_dst));
        strcpy(src, inet_ntoa(ip->ip_src));
        //record time packet was sent
        add_time(ip,id,ts,times);
        //set ID of first packet
        temp= ip->ip_id;
        first_id = (temp>>8)|(temp<<8);
        //Get MF flag value
        mf = (ip->ip_off & 0x0020) >> 5;
        //if MF is set, incerement total number of fragments
        if (mf == 1){
          fragments++;
        }
      //packet is a fragment of the first packet sent in traceroute
    } else if (first_id == id){
          //Get MF flag value
          mf = (ip->ip_off & 0x0020) >> 5;
          //increment total number of fragments
          fragments++;
          //get offset value
          temp = ip->ip_off & 0xFF1F;
          offset = (temp>>8)|(temp<<8);
          //calculate vaue of offset if there are no more fragments
          if(mf == 0){
            last_frag=offset*8;
          }
          //record time packet was sent
          add_time(ip,id,ts,times);
      //packet is outgoing, record time sent
    } else if (icmp->type == 8){
          //record time packet was sent
          add_time(ip,id,ts,times);
    //packet signifies that the destination has been reached  
    } else if ((icmp->type ==0)||(icmp->type ==3)){
          add_to_list(routers,packet,ip,protocols,ts,times);
          list_index--;
          return 0;
    }
  } else if (ip->ip_p == 17){
    
    if (first_id == 0 && ip->ip_ttl == 1){
      //first_id = 
      strcpy(ult_dst,inet_ntoa(ip->ip_dst));
      strcpy(src, inet_ntoa(ip->ip_src));
      add_time(ip,id,ts,times);
      //set ID of first packet
       temp= ip->ip_id;
       first_id = (temp>>8)|(temp<<8);
       //Get MF flag value
       mf = (ip->ip_off & 0x0020) >> 5;
       //if MF is set, incerement total number of fragments
       if (mf == 1){
          fragments++;
        }     
    }
    protocols[17] = 1;
    
    return 0;
  } else if (ip->ip_p == 6){
    protocols[6] = 1;
    return 0;
  } else {
    protocols[ip->ip_p] == 1;
    return 0;
  }
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
