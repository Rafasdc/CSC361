//Headers based from Programming with PCAP Library documentations and Lab Session 6

#define MAX_STR_LEN 100
#define MAX_HOPS 1000


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

struct router {
  int ttl;
  char ip_src[MAX_STR_LEN];
  char ip_dst[MAX_STR_LEN];
};

struct outgoing {
  struct timeval starting_time;
  struct timeval ending_time;
};


