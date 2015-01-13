#include<stdio.h>
#include<stdlib.h>
#include "net.h"
#include "netinet.h"
#include "ip6.h"
#include<stdlib.h>
#include <pcap.h>
#include<pthread.h>
#include<sys/types.h>
#include<sys/stat.h>	
#include<fcntl.h>
#include<errno.h>
#include<string.h>
#include<gtk/gtk.h>
#include<gdk/gdk.h>
#include<glib.h>
#include<winsock2.h>
#include<time.h>

#define STDINFLUSHLEN 512
#define ETHER_MTU 1514
#define FAILURE -1
#define MAX_PACKETS 1500
#define ETH_HDR_SIZE 14
#define IP6_HDR_SIZE 40
#define ICMP_HDR_SIZE 4
#define IGMP_HDR_SIZE 12
#define TCP_HDR_SIZE 20
#define UDP_HDR_SIZE 8
#define ARP_HDR_SIZE 8

#define MAXMSGSIZE 1600
#define FILECLOSEERROR EOF
#define VALOTHERTHANZERO 100
#define COMPILEFAIL -1
#define IPADDRSIZE 200
#define PORTSIZE 200
#define PROTOCOLSIZE 200
#define MAXBUFFSIZE 65535

enum ip_proto {ICMP = 0x01 ,IGMP = 0x02,TCP = 0x06,UDP = 0x11,ICMP6 = 0x3a};
enum ether_proto {IPV4 = 0x0800, IPV6 = 0x86DD, ARP = 0x0806};

struct ether_header *eth_in;
struct arphdr *arp_in;
struct ip *ip4_in;
struct ip6_hdr *ip6_in;
struct icmphdr *icmp_in;
struct icmp6_hdr *icmp6_in;
struct igmp *igmp_in;
struct tcphdr *tcp_in;
struct udphdr *udp_in;

int pkt_no;
int file_pkt_no;
int ip4_no;
int ip6_no;
int icmp_no;
int igmp_no;
int tcp_no;
int udp_no;
int arp_no;
int icmp6_no;
int http_no;
int ftp_no;
int dns_no;
int dhcp_no;
int others_nwl_no;
int others_tl_no;
int others_al_no;
int inter_flag; 
int breakflag;
unsigned long int pkt_len1;
int stat_fl;
int autoscroll;

char strErrbuf[PCAP_ERRBUF_SIZE];
char *intername;
char *strQname;
unsigned char final[1600];

pthread_t threadid1;
pthread_t threadid2;
pthread_t threadid3;

int iThread3Status;

pcap_t *Interhandle;	
bpf_u_int32 Netmask;

FILE *fp;

GtkWidget *text;
GtkTextBuffer *buff_dis;
GtkTextIter iter_dis;

GtkWidget *text_status;
GtkTextBuffer *buffer;
GtkTextIter iter;

GtkWidget *text_pktno;
GtkTextBuffer *b_pktno;
GtkTextIter i_pktno;

GtkWidget *text_ts;
GtkTextBuffer *b_ts;
GtkTextIter i_ts;

GtkWidget *text_src;
GtkTextBuffer *b_src;
GtkTextIter i_src;

GtkWidget *text_dst;
GtkTextBuffer *b_dst;
GtkTextIter i_dst;

GtkWidget *text_nwp;
GtkTextBuffer *b_nwp;
GtkTextIter i_nwp;

GtkWidget *text_tlp;
GtkTextBuffer *b_tlp;
GtkTextIter i_tlp;

GtkWidget *text_srcport;
GtkTextBuffer *b_srcport;
GtkTextIter i_srcport;

GtkWidget *text_dstport;
GtkTextBuffer *b_dstport;
GtkTextIter i_dstport;

GtkWidget *win_stats;

GtkWidget *text_alp;
GtkTextBuffer *b_alp;
GtkTextIter i_alp;

GtkWidget *entry_port;
GtkWidget *entry_addr;
GtkWidget* combo_box_proto;
GtkWidget *scrolledwindow1;
GtkWidget *scrolledwindow3;
GtkAdjustment *adjustment;
GtkAdjustment *adjustment1;

G_MODULE_EXPORT void init();
G_MODULE_EXPORT int filter(char *);
G_MODULE_EXPORT int protocol_filter();
G_MODULE_EXPORT int port_filter(GtkListStore *);
G_MODULE_EXPORT int ipaddr_filter(GtkListStore *);
G_MODULE_EXPORT void all_filter();
G_MODULE_EXPORT void interfaceDisp(GtkWidget *);
G_MODULE_EXPORT void callback( u_char *, const struct pcap_pkthdr* ,
    const u_char* );
G_MODULE_EXPORT void statistics();
G_MODULE_EXPORT void reset();
G_MODULE_EXPORT void *logfile(void *);
G_MODULE_EXPORT void fileopen();
G_MODULE_EXPORT void *capture(void *);
G_MODULE_EXPORT int interSelect(GtkComboBox *);
G_MODULE_EXPORT void uninit();

void addr_conv_src(unsigned int addr);
void addr_conv_dst(unsigned int addr);
void addr_conv(unsigned int addr);
void flush_file();
void eth_hdr();
void arp_hdr();
void ip4_hdr();
void icmp_hdr();
void igmp_hdr();
void tcp_hdr();
void udp_hdr();
void ipv6();
void icmp6();
void display_pkt();
void tcp();
void udp();
void flush_buffer();
