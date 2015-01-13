#include "header.h"

/*Union and Function to convert the IP address into dotted decimal format*/
union addc
{
    unsigned int ip_add;
    unsigned char add_char[4];
};

void addr_conv(unsigned int addr)
{
    union addc addc_in;
    int count = 0;

	addc_in.ip_add = addr;
    
    for(count = 0; count < 4; count++)
    {
        fprintf(fp,"%d",addc_in.add_char[count]);
        
        if (count != 3)
        {
            fprintf(fp,".");
            
        }
    }
}

void addr_conv_src(unsigned int addr)
{
    
    union addc addc_in;
	int count = 0;
    char ip4_addr[5];

    addc_in.ip_add = addr;
    gtk_text_buffer_insert (b_src, &i_src,"  ",-1);

    for(count = 0; count < 4; count++)
    {
        fprintf(fp,"%d",addc_in.add_char[count]);

        sprintf_s(ip4_addr,4, "%d",addc_in.add_char[count]);
        gtk_text_buffer_insert (b_src, &i_src,ip4_addr,strlen(ip4_addr));

        if (count != 3)
        {
            fprintf(fp,".");
            gtk_text_buffer_insert (b_src, &i_src,".",-1);
        }
    }
    gtk_text_buffer_insert (b_src, &i_src,"\n",-1);
}

void addr_conv_dst(unsigned int addr)
{
    union addc addc_in;
    
    int count = 0;
    char ip4_addr[5];
	addc_in.ip_add = addr;

    gtk_text_buffer_insert (b_dst, &i_dst,"  ",-1);

    for(count = 0; count < 4; count++)
    {
        fprintf(fp,"%d",addc_in.add_char[count]);

        sprintf_s(ip4_addr,4, "%d",addc_in.add_char[count]);
        gtk_text_buffer_insert (b_dst, &i_dst,ip4_addr,strlen(ip4_addr));

        if (count != 3)
        {
            fprintf(fp,".");
            gtk_text_buffer_insert (b_dst, &i_dst,".",-1);
        }
    }
    gtk_text_buffer_insert (b_dst, &i_dst,"\n",-1);
}

/*DESCRIPTION : Function to flush the file
  NAME        : flush_file
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void flush_file()
{
	FILE *fp_clear;

	rewind(fp);   //Moving the file pointer to the beginning of the file 
    fp_clear = fopen("PacketAnalyst.txt","w+");
	fclose(fp_clear);
    file_pkt_no = 0;
}    

/*DESCRIPTION : Function to extract and display the fields of Ethernet header
  NAME        : eth_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void eth_hdr()
{   
    int add_it = 0;

    fprintf(fp,"Destination MAC        :");

    for(add_it = 0; add_it <= 5; add_it++)
    {
        fprintf(fp,"%x\t",eth_in->ether_dhost[add_it]);
    }

    fprintf(fp,"\n");
    fprintf(fp,"Source MAC             :");

    for(add_it = 0; add_it <= 5; add_it++)
    {
        fprintf(fp,"%x\t",eth_in->ether_shost[add_it]);
    }

    fprintf(fp,"\n");
}

/*DESCRIPTION : Function to extract and display the fields of ARP header
  NAME        : arp_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void arp_hdr()
{
    int add_it = 0;
    char mac_addr[5]; 

    gtk_text_buffer_insert (b_src, &i_src,"  ",-1);

    for(add_it = 0; add_it <= 5; add_it++)
    {
        sprintf_s(mac_addr,4, "%x",eth_in->ether_shost[add_it]);
        gtk_text_buffer_insert (b_src, &i_src,mac_addr,strlen(mac_addr));

        if (add_it != 5)
        {
            gtk_text_buffer_insert (b_src, &i_src,":",-1);
        }
    }
    gtk_text_buffer_insert (b_src, &i_src,"\n",-1);
    gtk_text_buffer_insert (b_dst, &i_dst,"  ",-1);

    for(add_it = 0; add_it <= 5; add_it++)
    {
        sprintf_s(mac_addr,4, "%x",eth_in->ether_dhost[add_it]);
        gtk_text_buffer_insert (b_dst, &i_dst,mac_addr,strlen(mac_addr));

        if (add_it != 5)
        {
            gtk_text_buffer_insert (b_dst, &i_dst,":",-1);
        }
    }
    gtk_text_buffer_insert (b_dst, &i_dst,"\n",-1);

    fprintf(fp,"Hardware Type          :0x%x",ntohs(arp_in->ar_hrd));
    fprintf(fp,"(Ethernet)\n");
    fprintf(fp,"Protocol Type          :0x%x",ntohs(arp_in->ar_pro));

    if (ntohs(arp_in->ar_pro) == IPV4)
    { 
        fprintf(fp,"(IPv4)\n");
    }
    else if (ntohs(arp_in->ar_pro) == IPV6)
    {
       fprintf(fp,"(IPv6)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }

    fprintf(fp,"Hardware Address Length:0x%x\n",arp_in->ar_hln);
    fprintf(fp,"Protocol Format Length :0x%x\n",arp_in->ar_pln);
    fprintf(fp,"ARP opcode             :%d",ntohs(arp_in->ar_op));

    if (ntohs(arp_in->ar_op) == 1)
    {
        fprintf(fp,"(ARP request)\n");
    }
    else if (ntohs(arp_in->ar_op) == 2)
    {
        fprintf(fp,"(ARP reply)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }
}

/*DESCRIPTION : Function to extract and display the fields of IPv4 header
  NAME        : ip4_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void ip4_hdr()
{
    unsigned short int frag_offset = ntohs(ip4_in->ip_off);
    int ip_flag = 0;
    int ip_frag = 0;
  
    fprintf(fp,"Version                :%d\n",ip4_in->ip_v);
    fprintf(fp,"Source IP address      :");
    addr_conv_src(ip4_in->ip_src.u_addr);
    fprintf(fp,"\n");
    fprintf(fp,"Destination IP address :");
    addr_conv_dst(ip4_in->ip_dst.u_addr);
    fprintf(fp,"\n");       
    fprintf(fp,"Header Length          :%d(x 4)\n",ip4_in->ip_hl);
    fprintf(fp,"Total Length           :%d\n",ntohs(ip4_in->ip_len));
    fprintf(fp,"Identification         :0x%x\n",ntohs(ip4_in->ip_id));
    fprintf(fp,"Flags and offset       :0x%x\n",frag_offset);

    ip_flag = frag_offset & 0xf000;  
    fprintf(fp,"Flag                   :0x%x",ip_flag);

    if (ip_flag == 0x8000)
    {
        fprintf(fp,"(Reserved fragment flag)\n");
    }
    else if (ip_flag == 0x4000)
    {
        fprintf(fp,"(Don't fragment flag)\n");
    }
    else if (ip_flag == 0x2000)
    {
        fprintf(fp,"(More fragments flag)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }

    ip_frag = frag_offset & 0x0fff;
    fprintf(fp,"Fragmentation offset   :0x%x\n",ip_frag);
    fprintf(fp,"Time to live           :%d\n",ip4_in->ip_ttl);
    fprintf(fp,"Protocol               :%d\n",ip4_in->ip_p);
    fprintf(fp,"Header Checksum        :0x%x\n",ntohs(ip4_in->ip_sum));    
}

/*DESCRIPTION : Function to extract and display the fields of ICMP(v4) header
  NAME        : icmp_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void icmp_hdr()
{
    fprintf(fp,"Type                   :%d",icmp_in->type);

    if (icmp_in->type == 0)    
    {
        fprintf(fp,"(Echo Reply)\n");
    }
    else if (icmp_in->type == 3)
    {
        fprintf(fp,"(Destination Unreachable)\n");
    }
    else if (icmp_in->type == 8)
    {
        fprintf(fp,"(Echo Request)\n");
    }
    else if (icmp_in->type == 9)
    {
        fprintf(fp,"(Router Advertisement)\n");
    }
    else if (icmp_in->type == 10)
    {
        fprintf(fp,"(Router Solicitation)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }

    fprintf(fp,"Code                   :%d\n",icmp_in->code);
    fprintf(fp,"Checksum               :0x%x\n",ntohs(icmp_in->checksum));
}

/*DESCRIPTION : Function to extract and display the fields of IGMP header
  NAME        : igmp_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void igmp_hdr()
{
    fprintf(fp,"Type                   :0x%x",igmp_in->igmp_type);
    
    if (igmp_in->igmp_type == 0x11)
    {
        fprintf(fp,"(Membership Query)\n");
    }
    else if (igmp_in->igmp_type == 0x12 || igmp_in->igmp_type == 0x16)
    {
        fprintf(fp,"(Membership Report)\n");
    }
    else if (igmp_in->igmp_type == 0x17)
    {
        fprintf(fp,"(Leave Group message)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }

    fprintf(fp,"Code                   :0x%x\n",igmp_in->igmp_code);
    fprintf(fp,"Checksum               :0x%x\n",ntohs(igmp_in->igmp_cksum));
    fprintf(fp,"Group address          :");
    addr_conv(igmp_in->igmp_group.u_addr);
    fprintf(fp,"\n");
}

/*DESCRIPTION : Function to extract and display the fields of TCP header
  NAME        : tcp_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void tcp_hdr()
{
	int cnt1 = 0;
    char src_port[16];
    char dst_port[16];

	for(cnt1 = 0; cnt1 < 16; cnt1++)
	{
		src_port[cnt1] = 0;
		dst_port[cnt1] = 0;
	}

    fprintf(fp,"Source Port            :%d\n",ntohs(tcp_in->source));

    sprintf_s(src_port,15, "%d\n",ntohs(tcp_in->source));
    gtk_text_buffer_insert (b_srcport, &i_srcport,src_port,strlen(src_port));

    fprintf(fp,"Destination Port       :%d\n",ntohs(tcp_in->dest));

    sprintf_s(dst_port,15, "%d\n",ntohs(tcp_in->dest));
    gtk_text_buffer_insert (b_dstport, &i_dstport,dst_port,strlen(dst_port));

    fprintf(fp,"Sequence Number        :0x%x\n",ntohl(tcp_in->seq));
    fprintf(fp,"Acknowledgement Number :0x%x\n",ntohl(tcp_in->ack_seq));
    fprintf(fp,"Reserved               :0x%x\n",tcp_in->res1);
    fprintf(fp,"Data Offset            :0x%x\n",tcp_in->doff);
    fprintf(fp,"Fin                    :%d\n",tcp_in->fin);
    fprintf(fp,"Syn                    :%d\n",tcp_in->syn);
    fprintf(fp,"Rst                    :%d\n",tcp_in->rst);
    fprintf(fp,"Psh                    :%d\n",tcp_in->psh);
    fprintf(fp,"Ack                    :%d\n",tcp_in->ack);
    fprintf(fp,"Urg                    :%d\n",tcp_in->urg);
    fprintf(fp,"Reserved(2)            :0x%x\n",tcp_in->res2);
    fprintf(fp,"Window size            :0x%x\n",ntohs(tcp_in->window));
    fprintf(fp,"Checksum               :0x%x\n",ntohs(tcp_in->check));
    fprintf(fp,"Urgent Pointer         :0x%x\n",ntohs(tcp_in->urg_ptr));
}

/*DESCRIPTION : Function to extract and display the fields of UDP header
  NAME        : udp_hdr
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void udp_hdr()
{
    char src_port[16];
    char dst_port[16];
	int cnt1 = 0;

	for(cnt1 = 0; cnt1 < 16; cnt1++)
	{
		src_port[cnt1] = 0;
		dst_port[cnt1] = 0;
	}

    fprintf(fp,"Source Port            :%d\n",ntohs(udp_in->source));

    sprintf_s(src_port,15, "%d\n",ntohs(udp_in->source));
    gtk_text_buffer_insert (b_srcport, &i_srcport,src_port,strlen(src_port));

    fprintf(fp,"Destination Port       :%d\n",ntohs(udp_in->dest));

    sprintf_s(dst_port,15, "%d\n",ntohs(udp_in->dest));
    gtk_text_buffer_insert (b_dstport, &i_dstport,dst_port,strlen(dst_port));

    fprintf(fp,"Length                 :%d\n",ntohs(udp_in->len));
    fprintf(fp,"Checksum               :0x%x\n",ntohs(udp_in->check));
}

/*DESCRIPTION : Function to extract and display the fields of IPv6 header
  NAME        : ipv6
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void ipv6()
{
    int add_it = 0; 
    char ip6_addr[5];

    fprintf(fp,"Version                :6\n");
    fprintf(fp,"Payload Length         :");
    fprintf(fp,"%d\n",ntohs(ip6_in->ip6_ctlun.ip6_un1.ip6_un1_plen));
    fprintf(fp,"Next Header            :");
    fprintf(fp,"%d\n",ip6_in->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    fprintf(fp,"Hop limit              :");
    fprintf(fp,"%d\n",ip6_in->ip6_ctlun.ip6_un1.ip6_un1_hlim);
    fprintf(fp,"Source IP address      :");

    gtk_text_buffer_insert (b_src, &i_src,"  ",-1);
    for(add_it = 0; add_it < 16; add_it++)
    {
         fprintf(fp,"%x  ",ip6_in->ip6_src.__u6_addr8[add_it]);

         sprintf_s(ip6_addr,4, "%x",ip6_in->ip6_src.__u6_addr8[add_it]);
         gtk_text_buffer_insert (b_src, &i_src,ip6_addr,strlen(ip6_addr));

         if (add_it != 15)
        {
            gtk_text_buffer_insert (b_src, &i_src,":",-1);
        }
    }
    gtk_text_buffer_insert (b_src, &i_src,"\n",-1);

    fprintf(fp,"\n");
    fprintf(fp,"Destination IP address :");

    gtk_text_buffer_insert (b_dst, &i_dst,"  ",-1);
    for(add_it = 0; add_it < 16; add_it++)
    {
         fprintf(fp,"%x  ",ip6_in->ip6_dst.__u6_addr8[add_it]);

         sprintf_s(ip6_addr,4, "%x",ip6_in->ip6_dst.__u6_addr8[add_it]);
         gtk_text_buffer_insert (b_dst, &i_dst,ip6_addr,strlen(ip6_addr));

         if (add_it != 15)
        {
            gtk_text_buffer_insert (b_dst, &i_dst,":",-1);
        }
    }
    gtk_text_buffer_insert (b_dst, &i_dst,"\n",-1);
    fprintf(fp,"\n");   
}

/*DESCRIPTION : Function to extract and display the fields of ICMP(v6) header
  NAME        : icmp6
  RETURN TYPE : void
  ARGUMENTS   : void  
*/
void icmp6()
{          
    fprintf(fp,"Type                   :%d",icmp6_in->icmp6_type);

    if (icmp6_in->icmp6_type == 129)    
    {
        fprintf(fp,"(Echo Reply)\n");
    }
    else if (icmp6_in->icmp6_type == 1)
    {
        fprintf(fp,"(Destination Unreachable)\n");
    }
    else if (icmp6_in->icmp6_type == 128)
    {
        fprintf(fp,"(Echo Request)\n");
    }
    else if (icmp6_in->icmp6_type == 134)
    {
        fprintf(fp,"(Router Advertisement)\n");
    }
    else if (icmp6_in->icmp6_type == 133)
    {
        fprintf(fp,"(Router Solicitation)\n");
    }
    else if (icmp6_in->icmp6_type == 130)
    {
        fprintf(fp,"(Multicast Listener Query)\n");
    }
    else if (icmp6_in->icmp6_type == 131)
    {
        fprintf(fp,"(Multicast Listener Report)\n");
    }
    else if (icmp6_in->icmp6_type == 132)
    {
        fprintf(fp,"(Multicast Listener Done)\n");
    }
    else if (icmp6_in->icmp6_type == 143)
    {
        fprintf(fp,"(Multicast Listener Discovery (MLDv2) reports)\n");
    }
    else if (icmp6_in->icmp6_type == 135)
    {
        fprintf(fp,"(Neighbour Solicitation)\n");
    }
    else if (icmp6_in->icmp6_type == 136)
    {
        fprintf(fp,"(Neighbour Advertisement)\n");
    }
    else
    {
        fprintf(fp,"\n");
    }

    fprintf(fp,"Code                   :%d\n",icmp6_in->icmp6_code);
    fprintf(fp,"Checksum               :0x%x\n",ntohs(icmp6_in->icmp6_cksum));
}
