#include"header.h"

/*FUNCTION NAME :flush_buffer
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :flushes all textview buffers of glade file and resting corresponding iterators 
 */
void flush_buffer()
{
    GtkTextIter start,end;

    gtk_text_buffer_get_bounds (buffer, &start, &end);
    gtk_text_buffer_delete(buffer,&start,&end);
    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);

    gtk_text_buffer_get_bounds (b_pktno, &start, &end);
    gtk_text_buffer_delete(b_pktno,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_pktno, &i_pktno, 0);

    gtk_text_buffer_get_bounds (b_ts, &start, &end);
    gtk_text_buffer_delete(b_ts,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_ts, &i_ts, 0);

    gtk_text_buffer_get_bounds (b_nwp, &start, &end);
    gtk_text_buffer_delete(b_nwp,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_nwp, &i_nwp, 0);

    gtk_text_buffer_get_bounds (b_src, &start, &end);
    gtk_text_buffer_delete(b_src,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_src, &i_src, 0);

    gtk_text_buffer_get_bounds (b_dst, &start, &end);
    gtk_text_buffer_delete(b_dst,&start,&end); 
    gtk_text_buffer_get_iter_at_offset(b_dst, &i_dst, 0);

    gtk_text_buffer_get_bounds (b_tlp, &start, &end);
    gtk_text_buffer_delete(b_tlp,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_tlp, &i_tlp, 0);

    gtk_text_buffer_get_bounds (b_srcport, &start, &end);
    gtk_text_buffer_delete(b_srcport,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_srcport, &i_srcport, 0);

    gtk_text_buffer_get_bounds (b_dstport, &start, &end);
    gtk_text_buffer_delete(b_dstport,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_dstport, &i_dstport, 0);

    gtk_text_buffer_get_bounds (b_alp, &start, &end);
    gtk_text_buffer_delete(b_alp,&start,&end);
    gtk_text_buffer_get_iter_at_offset(b_alp, &i_alp, 0);

}

/*FUNCTION NAME :display_Pkt
 *ARGUMENTS     :void *
 *RETURN TYPE   :void *
 *DESCRIPTION   :thread receive a packet from buffer and format accordingly 
 */
void display_pkt()
{
    unsigned char buff[MAXMSGSIZE]; //to store a pkt received from global variable
    unsigned char *temp_buff = NULL;
    unsigned short int e_type = 0; //ethernet type
    unsigned short ip4_type = 0;  //protocol type (IPv4)  
    unsigned short ip6_type = 0;  //protocol type (IPv6)
    int recv_bytes = 0;//no. of bytes of packet
    int counter = 0;
    int count_data = 0; // no. of bytes in the temp_buff
    unsigned int ip_hlen = 0; 
    char cnt_pkt[10];
    int count = 0;
    struct ip6_hbh *hbh;
    struct ip6_dest *dest;
    struct ip6_rthdr *rt;
    struct ip6_frag *fg;
    int *len = NULL;
    char *date = NULL;
    char date1[30];

    for(count = 0; count < 10; count++)
    {
        cnt_pkt[count] = '\0';
    }

    /* Initializing all the elements of buff to NULL*/

    for (counter = 0; counter < 1600; counter++)
    {
        buff[counter] = '\0';   
    }
            
    {
		 recv_bytes = pkt_len1;
		 for (counter = 0; counter < 1600; counter++)
         {
              buff[counter] = final[counter];
         }
		
         /* Checking the no. of packets in the file.
          If it exceeds the limit, then flush the file
          else write the packets into the file
        */   

         gdk_threads_enter();

         if ( file_pkt_no >= MAX_PACKETS ) 
         {
             flush_file();
             flush_buffer();
         }
         fprintf(fp,"\n");
         fprintf(fp,"\n======================================================"
                        "======================"
                        "=====\n\n");
         /*Incrementing the packet counter*/
         fprintf(fp, "Packet Number: %d\n",(++pkt_no)); 
         sprintf(cnt_pkt,"%d\n", pkt_no);
         gtk_text_buffer_insert (b_pktno, &i_pktno,cnt_pkt,strlen(cnt_pkt));

         file_pkt_no++;  //Counting the no. of pkts written in the file
         temp_buff = buff;
         count_data = recv_bytes;  
           
         len = (int *)temp_buff;
         temp_buff = temp_buff + 4;

         date = (char *)temp_buff;
           
         strncpy_s(date1 ,30, date ,*len);
         date1[*len] = '\0';
         fprintf(fp,"Timestamp: %s\n",date1);

         strcat_s(date1,30,"\n");
         gtk_text_buffer_insert (b_ts, &i_ts,date1,strlen(date1));
          
         temp_buff = temp_buff + (*len) ;
           
         /* Display of Ethernet Header*/
         if(inter_flag == 1)
         {
	         fprintf(fp, "\nEthernet header\n");

             /*Typecasting the buffer pointer to ethernet header structure*/
	         eth_in  = (struct ether_header *)temp_buff;  
	         e_type = ntohs(eth_in->ether_type); 
	         eth_hdr();

             /* Incrementing the buffer pointer to point to the next header*/
	         temp_buff = temp_buff + ETH_HDR_SIZE;  
             /* Updating the no. of bytes yet to be displayed*/
	         count_data = count_data - ETH_HDR_SIZE; 
	    
	         if (e_type == IPV4 || e_type == IPV6)
	         {
                 fprintf(fp, "\nIP header\n");
                   
	             if (e_type == IPV4)
	             {
	                 /* Display of IPv4 Header based on the e_type value*/          
					 ip4_no++;   //Incrementing the IPv4 counter
               	     ip4_in = (struct ip *)temp_buff;
	                 ip4_type = (ip4_in->ip_p);
                     if((ip4_type == ICMP ) || (ip4_type == IGMP))
                     {
                            
                     }
                     else
                     {
                         gtk_text_buffer_insert (b_nwp, &i_nwp,"IPv4\n",-1);
                     }
		             ip4_hdr();
                     ip_hlen = ip4_in->ip_hl;
		             temp_buff = temp_buff + (ip_hlen * 4);
		             count_data = count_data - (ip_hlen * 4);

		             switch (ip4_type)
		             {
		                 case ICMP:

                             /*Display of ICMP Header based on the ip4_type*/

		                     fprintf(fp, "\nICMP header\n");                    
		                     icmp_no++;   //Incrementing the ICMP counter
	                         icmp_in = (struct icmphdr *)temp_buff;  
		                     icmp_hdr();

                             gtk_text_buffer_insert (b_nwp, &i_nwp,
                                                        "ICMP\n",-1);
                             gtk_text_buffer_insert (b_tlp, &i_tlp,"\n",-1);
                             gtk_text_buffer_insert (b_srcport, &i_srcport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_dstport, &i_dstport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);

		                     temp_buff = temp_buff + ICMP_HDR_SIZE;
		                     count_data = count_data - ICMP_HDR_SIZE;
		                     break;          
		             
		                 case IGMP:
                             /*Display of IGMP Header based on the ip4_type*/

		                     fprintf(fp, "\nIGMP header\n");
                             igmp_no++;  //Incrementing the IGMP counter
                             igmp_in = (struct igmp *)temp_buff;  
		                     igmp_hdr();
                             gtk_text_buffer_insert (b_nwp, &i_nwp,
                                                        "IGMP\n",-1);
                             gtk_text_buffer_insert (b_tlp, &i_tlp,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_srcport, &i_srcport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_dstport, &i_dstport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);

		                     temp_buff = temp_buff + IGMP_HDR_SIZE;
		                     count_data = count_data - IGMP_HDR_SIZE;
		                     break;  
		        
		                 case TCP:

                             /*Display of TCP Header based on the ip4_type*/

                             tcp_in = (struct tcphdr *)temp_buff;  
		                     tcp();

                             temp_buff = temp_buff + TCP_HDR_SIZE;
		                     count_data = count_data - TCP_HDR_SIZE;                       
                             break;  

		                 case UDP:

                             /*Display of UDP Header based on the ip4_type*/

                             udp_in = (struct udphdr *)temp_buff;  
		                     udp();

                             temp_buff = temp_buff + UDP_HDR_SIZE;
		                     count_data = count_data - UDP_HDR_SIZE;
                             break;

                         default:
                             fprintf(fp,"\nOthers\n");

                             gtk_text_buffer_insert (b_tlp, &i_tlp,
                                                        "Others\n",-1);
                             gtk_text_buffer_insert (b_srcport, &i_srcport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_dstport, &i_dstport,
                                                        "\n",-1);
                             gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);

                             /*Incrementing the counter for 
                             other transport layer protocols*/
                             others_tl_no++;      
                     }   
                 }    
	             else
	             {
                     /* Display of IPv6 Header based on the e_type value*/
	               
                     ip6_no++;   //Incrementing the IPv6 counter
                     ip6_in = (struct ip6_hdr *)temp_buff;
                     ip6_type = (ip6_in->ip6_ctlun.ip6_un1.ip6_un1_nxt);
                       
                     ipv6();
                
                     temp_buff = temp_buff + IP6_HDR_SIZE;
                     count_data = count_data - IP6_HDR_SIZE;
                     while (ip6_type == 0 || ip6_type == 60 || ip6_type == 43 || ip6_type == 44)
                     {
                         switch(ip6_type)
                         {
                             case 0: 
                                 
                                 hbh = (struct ip6_hbh *)temp_buff;  
                                 fprintf(fp,"Hop-by-hop extension header");
                                 ip6_type = hbh->ip6h_nxt;
                                 temp_buff = temp_buff + ((hbh->ip6h_len) * 8);
                                 count_data = count_data - ((hbh->ip6h_len) * 8);
                                 break;

                             case 60:
                                    
                                 dest = (struct ip6_dest *)temp_buff;  
                                 fprintf(fp,"Destination options extension header");
                                 ip6_type = dest->ip6d_nxt;
                                 temp_buff = temp_buff + ((dest->ip6d_len) * 8);
                                 count_data = count_data - ((dest->ip6d_len) * 8);
                                 break;

                             case 43:
                                    
                                 rt = (struct ip6_rthdr *)temp_buff;  
                                 fprintf(fp,"Routing extension header");
                                 ip6_type = rt->ip6r_nxt;
                                 temp_buff = temp_buff + ((rt->ip6r_len) * 8);
                                 count_data = count_data - ((rt->ip6r_len) * 8);
                                 break;

                             case 44:
                                    
                                 fg = (struct ip6_frag *)temp_buff;  
                                 fprintf(fp,"Fragment extension header");
                                 ip6_type = fg->ip6f_nxt;
                                 temp_buff = temp_buff + 8;
                                 count_data = count_data - 8;
                                 break;  
                            }
                        }   
                        if((ip6_type == ICMP6 ) || (ip6_type == IGMP))
                        {
                            
                        }
                        else
                        {
                            gtk_text_buffer_insert (b_nwp, &i_nwp,"IPv6\n",-1);
                        }                                 
                        switch (ip6_type)
		                {
                             case ICMP6:

                                 /*Display of ICMP Header based on the ip6_type*/                    
                              
                                 fprintf(fp, "\nICMP/MLDv2 header\n");
                                 icmp6_no++;
	 	                         icmp6_in = (struct icmp6_hdr *)temp_buff;  
		                         icmp6();

                                 gtk_text_buffer_insert (b_nwp, &i_nwp,
                                                     "ICMP/MLD\n",-1);
                                 gtk_text_buffer_insert (b_tlp, &i_tlp,
                                                     "\n",-1);
                                 gtk_text_buffer_insert (b_srcport, &i_srcport,
                                                      "\n",-1);
                                 gtk_text_buffer_insert (b_dstport, &i_dstport,
                                                      "\n",-1);
                                 gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);

		                         temp_buff = temp_buff + ICMP_HDR_SIZE;
		                         count_data = count_data - ICMP_HDR_SIZE;
		                         break;          
		         
		                     case TCP:
                           
                                 tcp_in = (struct tcphdr *)temp_buff;  
		                         tcp();

                                 temp_buff = temp_buff + TCP_HDR_SIZE;
		                         count_data = count_data - TCP_HDR_SIZE;
                                 break;  

		                    case UDP:
                                 udp_in = (struct udphdr *)temp_buff;  
		                         udp();

                                 temp_buff = temp_buff + UDP_HDR_SIZE;
		                         count_data = count_data - UDP_HDR_SIZE;
                                 break;

                             default:
                                 fprintf(fp,"\nOthers\n");

                                 gtk_text_buffer_insert (b_tlp, &i_tlp,"Others\n",-1);
                                 gtk_text_buffer_insert (b_srcport, &i_srcport,
                                                       "\n",-1);
                                 gtk_text_buffer_insert (b_dstport, &i_dstport,
                                                       "\n",-1);
                                 gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);

                                 others_tl_no++;        
						}   
	               }  
               }
               else if (e_type == ARP)
               {
                   /* Display of ARP Header based on the e_type value*/

	               fprintf(fp, "\nARP header\n");          
	               arp_no++;  //Incrementing the ARP counter
	               arp_in = (struct arphdr *)temp_buff;
	               arp_hdr();

                   gtk_text_buffer_insert (b_nwp, &i_nwp,"ARP\n",-1);
                   gtk_text_buffer_insert (b_srcport, &i_srcport,"\n",-1);
                   gtk_text_buffer_insert (b_dstport, &i_dstport,"\n",-1);
                   gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);
                   gtk_text_buffer_insert (b_tlp, &i_tlp,"\n",-1);

	               temp_buff = temp_buff + ARP_HDR_SIZE;
	               count_data = count_data - ARP_HDR_SIZE;
          
	           }
	           else
               {
	               fprintf(fp, "\nOthers\n");

	               gtk_text_buffer_insert (b_nwp, &i_nwp,"Others\n",-1);
                   gtk_text_buffer_insert (b_src, &i_src,"\n",-1);
                   gtk_text_buffer_insert (b_dst, &i_dst,"\n",-1);
                   gtk_text_buffer_insert (b_srcport, &i_srcport,"\n",-1);
                   gtk_text_buffer_insert (b_dstport, &i_dstport,"\n",-1);
                   gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);
                   gtk_text_buffer_insert (b_tlp, &i_tlp,"\n",-1);

                   /*Incrementing the counter for
                   other network layer protocols*/
	               others_nwl_no++;  
               } 

	            /* Displaying the payload */ 

	            fprintf(fp, "\nPayload\n");  
	    
	            for(counter = 0 ; counter < count_data; counter++ )
                    fprintf(fp,"%x\t",temp_buff[counter]);

           
           }//end of if(inter_name)
           else
           {
               fprintf(fp, "Others\n");

               gtk_text_buffer_insert (b_nwp, &i_nwp,"Others\n",-1);
               gtk_text_buffer_insert (b_src, &i_src,"\n",-1);
               gtk_text_buffer_insert (b_dst, &i_dst,"\n",-1);
               gtk_text_buffer_insert (b_srcport, &i_srcport,"\n",-1);
               gtk_text_buffer_insert (b_dstport, &i_dstport,"\n",-1);
               gtk_text_buffer_insert (b_alp, &i_alp,"\n",-1);
               gtk_text_buffer_insert (b_tlp, &i_tlp,"\n",-1);

               fprintf(fp, "\nPayload\n");  
	    
	           for(counter = 0 ; counter < count_data; counter++ )
                   fprintf(fp,"%x\t",temp_buff[counter]);
           }
           fflush(fp);  //FLushing the buffered data into the file
       
           temp_buff = NULL;
         
           gdk_threads_leave();
   }//end of while(1)

 // return NULL;
}

/*FUNCTION NAME :tcp
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :load tcp headers and increment counters of 
                 tcp ,http,ftp,dhcp and dns accordingly 
 */
void tcp()
{ 
    fprintf(fp, "\nTCP header\n");

    gtk_text_buffer_insert (b_tlp, &i_tlp,"TCP\n",-1);

    tcp_no++;   //Incrementing the TCP counter
    tcp_hdr();

    if (ntohs(tcp_in->source) == 80 || ntohs(tcp_in->dest) == 80 || 
        ntohs(tcp_in->source) == 8080 || ntohs(tcp_in->dest) == 8080)
    {
        fprintf(fp,"\nHTTP packet\n");
	gtk_text_buffer_insert (b_alp, &i_alp,"HTTP\n",-1);
        http_no++;   //Incrementing the HTTP counter
    }
    else if (ntohs(tcp_in->source) == 53 || ntohs(tcp_in->dest) == 53)
    {
        fprintf(fp,"\nDNS packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"DNS\n",-1);
        dns_no++;   //Incrementing the DNS counter
    }
    else if(ntohs(tcp_in->source) == 20 || ntohs(tcp_in->dest) == 20 || 
            ntohs(tcp_in->source) == 21 || ntohs(tcp_in->dest) == 21)
    {
        fprintf(fp,"\nFTP packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"FTP\n",-1);
        ftp_no++;   //Incrementing the FTP counter
    }
    else if (ntohs(tcp_in->source) == 67 || ntohs(tcp_in->dest) == 67 || 
             ntohs(tcp_in->source) == 68 || ntohs(tcp_in->dest) == 68)
    {
        fprintf(fp,"\nDHCP packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"DHCP\n",-1);
        dhcp_no++;  //Incrementing the DHCP counter
    }
    else
    {
        fprintf(fp,"\nOthers\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"Others\n",-1);
        /* Incrementing the counter for other 
           application layer protocols*/
        others_al_no++;    
    }
}

/*FUNCTION NAME :udp
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :load udp headers and increment counters of 
                 udp,http,ftp,dhcp and dns accordingly 
 */		         

void udp()
{

    fprintf(fp, "\nUDP header\n");
    gtk_text_buffer_insert (b_tlp, &i_tlp,"UDP\n",-1);
    udp_no++;   //Incrementing the UDP counter
		         
    udp_hdr();
    if (ntohs(udp_in->source) == 80 || ntohs(udp_in->dest) == 80 ||
        ntohs(udp_in->source) == 8080 || ntohs(udp_in->dest) == 8080)
    {
        fprintf(fp,"\nHTTP packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"HTTP\n",-1);
        http_no++;
    }
    else if (ntohs(udp_in->source) == 53 || ntohs(udp_in->dest) == 53)
    {
        fprintf(fp,"\nDNS packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"DNS\n",-1);
        dns_no++;
    }
    else if(ntohs(udp_in->source) == 20 || ntohs(udp_in->dest) == 20 ||
            ntohs(udp_in->source) == 21 || ntohs(udp_in->dest) == 21)
    {
        fprintf(fp,"\nFTP packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"FTP\n",-1);
        ftp_no++;
    }
    else if (ntohs(udp_in->source) == 67 || ntohs(udp_in->dest) == 67 ||
             ntohs(udp_in->source) == 68 || ntohs(udp_in->dest) == 68)
    {
        fprintf(fp,"\nDHCP packet\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"DHCP\n",-1);
        dhcp_no++;
    }
    else
    {
        fprintf(fp,"\nOthers\n");
        gtk_text_buffer_insert (b_alp, &i_alp,"Others\n",-1);
        others_al_no++;
    }
	        
}
