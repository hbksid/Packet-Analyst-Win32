struct inaddr
  {
    unsigned int u_addr;
  };

struct ip
  {
    unsigned char ip_hl:4;		/* header length */
    unsigned char ip_v:4;		/* version */
    unsigned char ip_tos;			/* type of service */
    unsigned short int ip_len;			/* total length */
    unsigned short int ip_id;			/* identification */
    unsigned short int ip_off;			/* fragment offset field */
#define	IP_RF 0x8000			/* reserved fragment flag */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
    unsigned char ip_ttl;			/* time to live */
    unsigned char ip_p;			/* protocol */
    unsigned short int ip_sum;			/* checksum */
    struct inaddr ip_src;
	struct inaddr ip_dst;	/* source and dest address */
  };


struct igmp {
  unsigned char igmp_type;             /* IGMP type */
  unsigned char igmp_code;             /* routing code */
  unsigned short int igmp_cksum;           /* checksum */
  struct inaddr igmp_group;      /* group address */
};

struct icmphdr
{
  unsigned char type;		/* message type */
  unsigned char code;		/* type sub-code */
  unsigned short int checksum;
  union
  {
    struct
    {
      unsigned short int id;
      unsigned short int sequence;
    } echo;			/* echo datagram */
    unsigned int gateway;	/* gateway address */
    struct
    {
      unsigned short int __unused;
      unsigned short int mtu;
    } frag;			/* path mtu discovery */
  } un;
};


struct tcphdr
  {
    unsigned short int source;
    unsigned short int dest;
    unsigned int seq;
    unsigned int ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short int res1:4;
    unsigned short int doff:4;
    unsigned short int fin:1;
    unsigned short int syn:1;
    unsigned short int rst:1;
    unsigned short int psh:1;
    unsigned short int ack:1;
    unsigned short int urg:1;
    unsigned short int res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    u_int16_t doff:4;
    u_int16_t res1:4;
    u_int16_t res2:2;
    u_int16_t urg:1;
    u_int16_t ack:1;
    u_int16_t psh:1;
    u_int16_t rst:1;
    u_int16_t syn:1;
    u_int16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    unsigned short int window;
    unsigned short int check;
    unsigned short int urg_ptr;
};


struct udphdr
{
  unsigned short int source;
  unsigned short int dest;
  unsigned short int len;
  unsigned short int check;
};
