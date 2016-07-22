//Headers based from Programming with PCAP Library documentations and Lab Session 6

#define MAX_STR_LEN 100
#define MAX_HOPS 1000
#define MAX_PROTOCOLS 30


/* TCP Header */
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

struct outgoing {
  struct ip *ip;
  int id;
  struct timeval time_sent;
};

struct router {
  const unsigned char*packet;
  char src_addr[MAX_STR_LEN];
  uint16_t port_src;
  uint16_t port_dst;
  int protocols[MAX_HOPS];
  struct timeval time_sent;
  struct outgoing *times;
};


struct router_ordered {
  struct router router;
};

struct RTT {
  char src_addr[MAX_STR_LEN];
  char dst_addr[MAX_STR_LEN];
  double time;
  double total_hops;
  double times[MAX_HOPS];
};

struct mean_sd{
  double mean;
  double sd;
}





/*
void add_to_list(routers,const unsigned char*packet, struct ip *ip, int protocol, struct timeval ts,struct outgoing times[MAX_HOPS]){
  routers[list_index].packet = packet;
  routers[list_index].ip = packet;
  routers[list_index].protocol = protocol;
  routers[list_index].time_sent = ts;
  routers[list_index].times = times;
}


        routers[list_index].packet = packet;
        routers[list_index].ip = ip;
        routers[list_index].protocol = *protocols;
        routers[list_index].time_sent = ts;
        routers[list_index].times = times;
*/
