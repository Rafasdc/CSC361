#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>

#include "math.h"
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
int list_index_udp = 0;
int first_id;
int echo;
char src[MAX_STR_LEN];
struct RTT RTTs[MAX_STR_LEN];
struct router udps[MAX_HOPS];
int max_ttl = 0;

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
  struct router routers_ordered[MAX_STR_LEN];
  int i=0;
  for(; i< list_index+1; i++){
    //33434 || udp->uh_dport <= 33534
    if (routers[i].port_dst != 0 && (routers[i].port_dst >= 33434 && routers[i].port_dst <= 33534)  ){
      routers_ordered[routers[i].port_dst - 33434] = routers[i];
    }
    //printf("%d\n", routers[i].port_dst - 33434);
    //printf("  router %d with dest port %d : %s \n",i, routers[i].port_dst, routers[i].src_addr);
  }

  if (echo == 1){
    i = 0;
    for(; i < list_index+1; i++){
      //printf("%d\n", 1);

      routers_ordered[i] = routers[i];
      //printf("TTL IS %d and j %d\n", routers_ordered[i].ttl,i);
    }
  }
  //printf("after echo \n");

  int j = 0;
  for(; j <  MAX_STR_LEN; j++){
    if (routers_ordered[j].port_dst == 0 && echo == 0){
      continue;
    } else {
      //printf("udp src port is  %d and icmp src port is %d \n", udps[j].port_src, routers_ordered[j].port_src );

      if (udps[j].port_src == routers_ordered[j].port_src){
        //printf("TTL IS %d and j %d\n", udps[j].ttl,j);
        if (udps[j].ttl > max_ttl){
          max_ttl = udps[j].ttl;
        }
        strcpy(RTTs[j].src_addr,src);
        strcpy(RTTs[j].dst_addr, routers_ordered[j].src_addr);

        time_t start_time = udps[j].time_sent.tv_sec; //time of first packet
        double startt = (double)start_time;
        startt +=  (1.0/1000000)*udps[j].time_sent.tv_usec;


        time_t end_time = routers_ordered[j].time_sent.tv_sec;
        double endt = (double)end_time;
        endt += (1.0/1000000)*routers_ordered[j].time_sent.tv_usec;

        //printf("%f\n",endt);
        double duration = endt-startt;
        RTTs[j].time = duration;
      }
    }

  }

  j = 0;
  for(; j <  MAX_STR_LEN; j++){
    if (echo == 1) {
      //printf("Windows packet\n");
      //match sequece and do same as below
      if (routers_ordered[j].ttl != 0){
        if (routers_ordered[j].ttl < 20 && routers_ordered[j].ttl > max_ttl){
          max_ttl = routers_ordered[j].ttl;
        }
        //printf("TTL IS %d and j %d\n", routers_ordered[j].ttl,j);
        strcpy(RTTs[j].src_addr,src);
        strcpy(RTTs[j].dst_addr, routers_ordered[j].src_addr);

        time_t start_time = routers_ordered[j].time_sent.tv_sec; //time of first packet
        double startt = (double)start_time;
        startt +=  (1.0/1000000)*routers_ordered[j].time_sent.tv_usec;


        time_t end_time = routers_ordered[j+1].time_sent.tv_sec;
        double endt = (double)end_time;
        endt += (1.0/1000000)*routers_ordered[j+1].time_sent.tv_usec;

        //printf("%f\n",endt);
        double duration = endt-startt;
        if (duration > 0){
          RTTs[j].time = duration;
          //printf("%f\n", duration);
        }

      }
    }

  }

  j=0;
  i=0;
  int time_pos = 0;
  int dst_pos = 0;
  int comp = 0;
  int curr_ttl = 0;
  int first = 0;
  int i_count;
  struct RTT rtt_for_calc[MAX_STR_LEN];
  for(;j<MAX_STR_LEN; j++){

    //curr_ttl = udps[j].ttl;
    if (RTTs[j].src_addr != NULL && RTTs[j].src_addr[0] != '\0' && echo == 0){
      printf("TTL IS %d and j %d\n", udps[j].ttl,j);
      if (j==0){
        curr_ttl = udps[j].ttl;
        first = 1;
      }
      //printf("CURR TTL is %d\n ", curr_ttl);
      if (curr_ttl == udps[j].ttl){

        //printf("IN here\n");
        //printf("CURR TTL is %d\n ", curr_ttl);
        if (first == 1){
          rtt_for_calc[curr_ttl] = RTTs[j];
          first = 0;
        }
        rtt_for_calc[curr_ttl].times[time_pos] = RTTs[j].time;
        //printf("%f\n", rtt_for_calc[curr_ttl].times[time_pos]);

        rtt_for_calc[j].total_hops += 1;
        rtt_for_calc[curr_ttl].to_print = 1;
        //dst_pos = j;
        time_pos++;
        rtt_for_calc[curr_ttl].total_hops = time_pos;

      } else {
        curr_ttl = udps[j].ttl;
        time_pos = 0;
        rtt_for_calc[curr_ttl] = RTTs[j];
        rtt_for_calc[curr_ttl].times[time_pos] = RTTs[j].time;
        //printf("%f\n", rtt_for_calc[curr_ttl].times[time_pos]);
        rtt_for_calc[curr_ttl].to_print = 1;
        //curr_ttl = j;
        time_pos++;
        rtt_for_calc[j].total_hops = time_pos;
        //rtt_for_calc[curr_ttl].total_hops = time_pos;

      }
    } else if(echo == 1){
      if(routers_ordered[j].ttl < 20 && routers_ordered[j].ttl != 0){
        printf("TLL is %d \n", routers_ordered[j].ttl);
        if (i==0){
          curr_ttl = routers_ordered[j].ttl;
          first = 1;
        }
        //printf("CURR TTL is %d\n ", curr_ttl);
        if (curr_ttl == routers_ordered[j].ttl){

          //printf("IN here\n");
          //printf("CURR TTL is %d\n ", curr_ttl);
          if (first == 1){
            rtt_for_calc[curr_ttl] = RTTs[j];
            first = 0;
          }
          rtt_for_calc[curr_ttl].times[time_pos] = RTTs[j].time;
          //printf("%f\n", rtt_for_calc[curr_ttl].times[time_pos]);

          rtt_for_calc[j].total_hops += 1;
          rtt_for_calc[curr_ttl].to_print = 1;
          //dst_pos = j;
          time_pos++;
          rtt_for_calc[curr_ttl].total_hops = time_pos;

        } else {
          curr_ttl = udps[j].ttl;
          time_pos = 0;
          rtt_for_calc[curr_ttl] = RTTs[j];
          rtt_for_calc[curr_ttl].times[time_pos] = RTTs[j].time;
          //printf("%f\n", rtt_for_calc[curr_ttl].times[time_pos]);
          rtt_for_calc[curr_ttl].to_print = 1;
          //curr_ttl = j;
          time_pos++;
          rtt_for_calc[j].total_hops = time_pos;
          //rtt_for_calc[curr_ttl].total_hops = time_pos;

        }
      }
    }

  }



  i=1;
  //printf("max_ttl is %d \n", max_ttl);
  for(; i < max_ttl+1; i++){
      printf("  router %d : %s \n",i, rtt_for_calc[i].dst_addr);
  }

  //printf("  router %d with dest port %d : %s \n",i, routers[i].port_dst, routers[i].src_addr);

  //printf("  router %d with dest port %d : %s \n",i, routers[i].port_dst, routers[i].src_addr);

  printf("\nThe values in the protocol field of the IP headers:\n");


  j = 0;
  for(; j < MAX_PROTOCOLS; j++){
    if (protocols[j] == 1){
        if (j == 1){
        printf("%d:ICMP \n", j);
      } else if (j==6){
        printf("%d:TCP\n", j);
      } else if (j==17){
        printf("%d:UDP\n", j);
      } else {
        printf("%d\n", j);
      }
    }
  }

  printf("\nThe number of fragments created from the original datagram is: %d \n", fragments);
  printf("The offset of the last frament is: %d \n", last_frag);


        /*
        time_t start_time = connections[i].rtt_array[j].starting_time.tv_sec;
        double startt = (double)start_time;
        startt += (1.0/1000000)*connections[i].rtt_array[j].starting_time.tv_usec;
        startt -= init_time;
        time_t end_time = connections[i].rtt_array[j].ending_time.tv_sec;
        double endt = (double)end_time;
        endt +=(1.0/1000000)*connections[i].rtt_array[j].ending_time.tv_usec;
        endt -= init_time;
        double duration = endt-startt;
        */
  //time_t start_time = times[0].time_sent.tv_sec; //time of first packet
  //double startt = (double)start_time;
  //printf("%f\n",startt);
  //startt +=  (1.0/1000000)*times[0].time_sent.tv_usec;











  i=0;
  for (;i<MAX_STR_LEN; i++){
    if(rtt_for_calc[i].to_print == 1){
      printf("%d\n",i);
      int a = 0;
      double mean = 0;
      double mean_for_sd = 0;
      double sum_u_mean = 0;
      double sd = 0;
      double x = 0;
      double x_mean = 0;
      double x_mean_2 = 0;
      int t_hops = rtt_for_calc[i].total_hops;
      //printf("Total hops %d\n", t_hops);
      for(;a<t_hops;a++){
        //printf("%d %f\n",a,rtt_for_calc[i].times[a]);
        mean += rtt_for_calc[i].times[a];
      }
      rtt_for_calc[i].mean = mean/t_hops;
      mean_for_sd = mean/t_hops;
      mean_for_sd *= 1000;
      //printf(" mean is %f \n", mean);
      int b = 0;
      for(;b<t_hops;b++){
        //printf("%d %f\n",a,rtt_for_calc[i].times[a]);
        x = rtt_for_calc[i].times[b]*1000;
        //printf("x is %f\n", x);
        x_mean = x-mean_for_sd;
        //printf("x - mean is %f\n", x_mean);
        x_mean_2 = (x_mean)*(x_mean);
        //printf("x_mean_2 is %f \n", x_mean_2);

        sum_u_mean += x_mean_2;
      }
      //printf("sum mean is %f \n", sum_u_mean);
      sd = sqrt(sum_u_mean/t_hops);
      //printf("sd is %f \n", sd);
      rtt_for_calc[i].sd = sd;

      printf("The avg RTT between %s and %s  is: %f ms, the s.d is: %f ms \n",rtt_for_calc[i].src_addr,rtt_for_calc[i].dst_addr,rtt_for_calc[i].mean*1000, rtt_for_calc[i].sd);
    }
  }


}




int parse_packet(const unsigned char *packet, unsigned int capture_len, struct router routers[MAX_HOPS],
 int protocols [MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]){

  struct ip *ip; //ip header
  unsigned int IP_header_length; //ip header lenglist_index++;th


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
    return 0;
  }


  return 1;

}

void add_time(struct ip *ip, int id, struct timeval ts,struct outgoing times[MAX_HOPS] ){
  times[fragments].ip = ip;
  times[fragments].id = id;
  times[fragments].time_sent = ts;
}

void add_to_list(struct router routers[MAX_HOPS],const unsigned char*packet, struct ip *ip, int protocols[MAX_HOPS], struct timeval ts,struct outgoing times[MAX_HOPS]){

      packet+=20; //8 bytes ICMP, 20 bytes IP
      struct udphdr *udp;
      udp = (struct udphdr*)packet;
      //printf("%d\n", ntohs(udp->uh_dport));

      routers[list_index].packet = packet;
      strcpy(routers[list_index].src_addr ,inet_ntoa(ip->ip_src));
      routers[list_index].port_src =  ntohs(udp->uh_sport);
      routers[list_index].port_dst =  ntohs(udp->uh_dport);
      //routers[list_index].protocols = *protocols;
      routers[list_index].time_sent = ts;
      routers[list_index].times = times;
      routers[list_index].ttl = ip->ip_ttl;
}

void add_to_list_udp(struct udphdr *udp, struct ip *ip, int protocols[MAX_HOPS], struct timeval ts,struct outgoing times[MAX_HOPS]){



      //packet+=28; //8 bytes ICMP, 20 bytes IP
      //struct udphdr *udp;
      //udp = (struct udphdr*)packet;
      //printf("%d\n", ntohs(udp->uh_dport));

      //udps[list_index].packet = packet;
      strcpy(udps[list_index_udp].src_addr ,inet_ntoa(ip->ip_src));
      udps[list_index_udp].port_src =  ntohs(udp->uh_sport);
      udps[list_index_udp].port_dst =  ntohs(udp->uh_dport);

      //udps[list_index_udp].protocols = *protocols;
      udps[list_index_udp].time_sent = ts;
      udps[list_index_udp].times = times;

      udps[list_index_udp].ttl = ip->ip_ttl;
}

int analyze_packet (struct ip *ip, const unsigned char*packet,struct router routers[MAX_HOPS],
  int protocols[MAX_STR_LEN], struct timeval ts, struct outgoing times[MAX_HOPS]){

  //printf("In analyze packet\n");
  struct icmphdr *icmp;
  struct udphdr *udp;
  uint16_t port;
  unsigned short temp,id,offset;
  struct ip *ic_ip;
  int mf;
  //printf("ip->ip_p is %d \n",ip->ip_p);

  //get ID of packet
  temp = ip->ip_id;
  id = (temp>>8)|(temp<<8);

  //pakcet if ICMP
  if(ip->ip_p == 1){
    //printf("ICMP with id is %d\n", id );
    //printf("Creating ICMP\n");
    icmp = (struct icmphdr*) packet;
    //printf("ICMP type is %d \n",icmp->type);

    mf = (ip->ip_off & 0x0020) >> 5;
    //printf(" MF flag is %d\n",mf );
    //add protocol
    protocols[1] = 1;

    //packet timed out
      //printf("ICMP type is %d \n", icmp->type);
    if(icmp->type == 11){
      //add intermiediate router to list
        //printf("%s\n", inet_ntoa(ip->ip_src));

        //printf("%s\n", inet_ntoa(ip->ip_src));
        packet += 8;
        ic_ip = (struct ip*) packet;
        //printf("%d\n", ip->ip_ttl);
        mf = (ic_ip->ip_off & 0x0020) >> 5;
        if (mf == 1){
          routers[list_index].fragments++;
        }


        add_to_list(routers,packet,ip,protocols,ts,times);
        //routers[list_index].sequence = icmp->sequence;
        list_index++;



    //first packet sent in trace route
    } else if ((icmp->type == 8) && (ip->ip_ttl == 1) && (first_id == 0)){
      //printf("IN here\n" );
      echo = 1;
        //set source and ultimate destination address
        strcpy(ult_dst,inet_ntoa(ip->ip_dst));
        strcpy(src, inet_ntoa(ip->ip_src));
        //record time packet was sent
        add_to_list(routers,packet,ip,protocols,ts,times);
        //routers[list_index].sequence = icmp->sequence;
        list_index++;
        add_time(ip,id,ts,times);
        //set ID of first packet
        temp= ip->ip_id;
        first_id = (temp>>8)|(temp<<8);
        //Get MF flag value
        mf = (ip->ip_off & 0x0020) >> 5;
        //if MF is set, incerement total number of fragments
        if (mf == 1){
          routers[list_index].fragments++;
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
          //packet += 8;
          //ic_ip = (struct ip*) packet;
          //printf("%d\n", ip->ip_ttl);
          add_to_list(routers,packet,ip,protocols,ts,times);
          list_index++;
          add_time(ip,id,ts,times);
    //packet signifies that the destination has been reached
    } else if ((icmp->type ==0)||(icmp->type ==3)){
          add_to_list(routers,packet,ip,protocols,ts,times);
          //routers[list_index].sequence = icmp->sequence;
          list_index++;
          return 1;
    }
  } else if (ip->ip_p == 17){

    struct udphdr *udp;
    udp = (struct udphdr*)packet;

   //printf("%d\n",ntohs(udp->uh_dport) >= 33434 && ntohs(udp->uh_dport));

    if ((ntohs(udp->uh_dport) >= 33434 && ntohs(udp->uh_dport) <= 33534)){
      //printf("UDP with id is %d\n", id );
      if (first_id == 0 && ip->ip_ttl == 1 ){
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
      mf = (ip->ip_off & 0x0020) >> 5;
      if (mf == 1){
        fragments++;
      }
      //printf("%d\n", ntohs(udp->uh_dport));
      //printf("%d\n", ntohs(udp->uh_sport));
      add_to_list_udp(udp,ip,protocols,ts,times);
      list_index_udp++;


    }
    //printf("First ID is %d and id is %d \n", first_id, id);

    //printf(" MF flag is %d\n",mf );

    protocols[17] = 1;
        //udp = (struct udphdr*)packet;


    return 1;
  } else if (ip->ip_p == 6){
    protocols[6] = 1;
    return 1;
  } else {
    if (ip->ip_p < 31){
      protocols[ip->ip_p] == 1;
    }
    return 1;
  }
  //printf("In here\n");
  return 1;
}
