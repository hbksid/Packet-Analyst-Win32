
struct in6addr
{
    unsigned char	__u6_addr8[16];
};

struct ip6_hdr
  {
    union
      {
	struct ip6_hdrctl
	  {
	    unsigned int ip6_un1_flow;   /* 4 bits version, 8 bits TC,
					20 bits flow-ID */
	    unsigned short int ip6_un1_plen;   /* payload length */
	    unsigned char  ip6_un1_nxt;    /* next header */
	    unsigned char  ip6_un1_hlim;   /* hop limit */
	  } ip6_un1;
	unsigned char ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6addr ip6_src;      /* source address */
    struct in6addr ip6_dst;      /* destination address */
  };

struct ip6_hbh
  {
    unsigned char ip6h_nxt;		/* next header.  */
    unsigned char ip6h_len;		/* length in units of 8 octets.  */
    /* followed by options */
  };
struct ip6_dest
  {
    unsigned char ip6d_nxt;		/* next header */
    unsigned char ip6d_len;		/* length in units of 8 octets */
    /* followed by options */
  };

struct ip6_rthdr
  {
    unsigned char ip6r_nxt;		/* next header */
    unsigned char ip6r_len;		/* length in units of 8 octets */
    unsigned char ip6r_type;		/* routing type */
    unsigned char ip6r_segleft;	/* segments left */
    /* followed by routing type specific data */
  };

struct ip6_frag
  {
    unsigned char ip6f_nxt;		/* next header */
    unsigned char ip6f_reserved;	/* reserved field */
    unsigned short int  ip6f_offlg;	/* offset, reserved, and flag */
    unsigned int  ip6f_ident;	/* identification */
  };



struct icmp6_hdr
  {
    unsigned char icmp6_type;   /* type field */
    unsigned char icmp6_code;   /* code field */
    unsigned short int icmp6_cksum;  /* checksum field */
    union
      {
	unsigned int icmp6_un_data32[1]; /* type-specific field */
	unsigned short int icmp6_un_data16[2]; /* type-specific field */
	unsigned char icmp6_un_data8[4];  /* type-specific field */
      } icmp6_dataun;
  };
