//Headers based from Programming with PCAP Library documentations and Lab Session 6

#define MAX_STR_LEN 100
#define MAX_NUM_CONNECTION 1000


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

struct rtt_info{
  struct timeval starting_time;
  struct timeval ending_time;
  int first_seq;
  int seq;
  int ack;
  int fin_count;
  int syn_count;
  int looking_syn_ack;
  int looking_match_seq;
};

struct connection{
  char ip_src[MAX_STR_LEN];  /*source ip*/
  char ip_dst[MAX_STR_LEN];  /*destination ip*/
  uint16_t port_src;
  uint16_t port_dst;
  int syn_count;
  int fin_count;
  int rst_count;
  struct timeval starting_time;
  struct timeval ending_time;
  double duration;
  int num_packet_src;     /*number of packets sent out by source*/
  int num_packet_dst;     /*number of packets sent out by destination*/
  int num_total_packets;
  int cur_data_len_src;   /*num data bytes*/
  int cur_data_len_dst;   /*num data bytes*/
  int cur_total_data_len;
  uint16_t max_win_size;  /*max window size*/
  uint16_t min_win_size;  /*min window size*/
  double sum_win_size;
  struct rtt_info rtt_array[MAX_NUM_CONNECTION/4]; /*assume 1000*/
  int rtt_array_len;    /*the size of the rtt_ary_src array*/
  int is_set;
};
