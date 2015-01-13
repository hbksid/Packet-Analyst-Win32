#include "header.h"

char str[20] = "\0";
char *str_buff = NULL;
char *strPortno1 = NULL;
char *strProtoTemp = NULL;
char *strIpAddrTemp = NULL;

/*
/*FUNCTION NAME :init
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :file open, semaphore creation, global variable
                 initializations
 */ 
void init()
{
    iThread3Status = VALOTHERTHANZERO;
    intername ="\0";
    Interhandle = NULL;
    stat_fl =0;
    autoscroll = 0; 

    fp = fopen("PacketAnalyst.txt","w+");
    if(fp == NULL)
    {
	   
       perror("\nERROR : FILE OPEN FAILED :"); 
       exit(0);
    }

 /*creating the buffer references of the textviews used in the application
 * for notifications in gui window*/
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_status)); 
    gtk_text_buffer_get_iter_at_offset(buffer, &iter, 0);

//textviews in the gui window for overall details of the packets
    b_pktno = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_pktno)); 
    gtk_text_buffer_get_iter_at_offset(b_pktno, &i_pktno, 0);
    
    b_ts = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_ts)); 
    gtk_text_buffer_get_iter_at_offset(b_ts, &i_ts, 0);

    b_src= gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_src)); 
    gtk_text_buffer_get_iter_at_offset(b_src, &i_src, 0);

    b_dst = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_dst)); 
    gtk_text_buffer_get_iter_at_offset(b_dst, &i_dst, 0);

    b_nwp = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_nwp)); 
    gtk_text_buffer_get_iter_at_offset(b_nwp, &i_nwp, 0);

    b_tlp = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_tlp)); 
    gtk_text_buffer_get_iter_at_offset(b_tlp, &i_tlp, 0);

    b_srcport = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_srcport)); 
    gtk_text_buffer_get_iter_at_offset(b_srcport, &i_srcport, 0);

    b_dstport = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_dstport)); 
    gtk_text_buffer_get_iter_at_offset(b_dstport, &i_dstport, 0);

    b_alp = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_alp)); 
    gtk_text_buffer_get_iter_at_offset(b_alp, &i_alp, 0);
}

/*FUNCTION NAME :filter
 *ARGUMENTS     :character pointer :strProto
 *RETURN TYPE   :void 
 *DESCRIPTION   :setting the filter using pcap lib functions :pcap_compile () & pcap_setfilter()
 */
int filter(char *strProto)
{
    int iCompileStatus = VALOTHERTHANZERO;
    int iSetFilterStatus = VALOTHERTHANZERO;
    int iOptimize = 1;
    struct bpf_program stFilterProg;

    if(Interhandle == NULL)
    {
        str_buff = "\nCapture not started in any Interface ";
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
        return 0;
    }
//compiling the "filter string" to be set for the filter
    iCompileStatus = pcap_compile( Interhandle , &stFilterProg , strProto, 
                                   iOptimize , Netmask );
    if(iCompileStatus == COMPILEFAIL)
    {
        str_buff = "\nFilter could not be set";
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff)); 
    }
    else
    {
       //setting the filter for the interface
        iSetFilterStatus = pcap_setfilter( Interhandle , &stFilterProg );
    }
    return 0;
}

/*FUNCTION NAME :protocol_filter
 *ARGUMENTS     :GtkComboBox * :combo_box_proto
 *RETURN TYPE   :int
 *DESCRIPTION   :setting the "filter string" for protocols supported by the application
 */
int protocol_filter()
{
    char strProto[PROTOCOLSIZE] = "\0";
    
    gtk_entry_set_text((GtkEntry *)entry_port,"");
    gtk_entry_set_text((GtkEntry *)entry_addr,"");

    strProtoTemp = gtk_combo_box_get_active_text((GtkComboBox *)combo_box_proto); 
    if((strcmp(strProtoTemp,"\0")) == 0)
    {
         str_buff = "\nSelect a protocol ";
         gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
         return 0;
    }

    if ((strcmp(strProtoTemp,"http\0")) == 0)
    {
        strncpy(strProto,"port 8080 or port 80",20);
    }
    else if ((strcmp(strProtoTemp,"ftp")) == 0)
    {
        strncpy(strProto,"port 20 or port 21",20);
    }
    else if ((strcmp(strProtoTemp,"dhcp")) == 0)
    {
        strncpy(strProto,"port 67 or port 68",20);
    }
    else if ((strcmp(strProtoTemp,"dns")) == 0)
    {
        strncpy(strProto,"port 53",20);
    }
    else
    {
        strncpy(strProto,strProtoTemp,20);
    }
    strProto[19] = '\0';
    filter(strProto);
    return 0;
}

/*FUNCTION NAME :port_filter
 *ARGUMENTS     :GtkEntry * :combo_box_proto
 *RETURN TYPE   :int
 *DESCRIPTION   :setting the "filter string" for port no
 */
int port_filter(GtkListStore *list1)
{
    char strPortno[PORTSIZE] = "\0";  

    gtk_entry_set_text((GtkEntry *)entry_addr,""); 
    gtk_combo_box_set_active((GtkComboBox *)combo_box_proto,12);

//getting the port no from the user
    strPortno1 = (char *) gtk_entry_get_text((GtkEntry *)entry_port);
   
    if((strcmp(strPortno1 ,"\0")) == 0)
    {
        str_buff = "\nEnter the Port Number ";
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
        return 0;
    }
/*setting the "filter string" as required by libpcap lib function pcap_compile 
for port no*/
    strcpy(strPortno,"port ");
    strncat(strPortno,strPortno1,5);
    filter(strPortno);
    strcpy(strPortno,"");

    return 0;
}
 
/*FUNCTION NAME :ipaddr_filter
 *ARGUMENTS     :GtkEntry * :entry_addr
 *RETURN TYPE   :int
 *DESCRIPTION   :setting the "filter string" for given ip address
 */
int ipaddr_filter(GtkListStore *list1)
{
   char strIpAddr[IPADDRSIZE] = "\0";   
    
   gtk_entry_set_text((GtkEntry *)entry_port,"");
   gtk_combo_box_set_active((GtkComboBox *)combo_box_proto,12);

    strIpAddrTemp = (char *) gtk_entry_get_text((GtkEntry *)entry_addr);
    if(strcmp(strIpAddrTemp ,"\0") == 0)
    {
        str_buff = "\nEnter the IP Address";
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
        return 0;
    } 
    strcpy(strIpAddr, "ip host ");
    strncat(strIpAddr,strIpAddrTemp ,16);
    filter(strIpAddr);
    strcpy(strIpAddr,"");

    return 0;
}    

G_MODULE_EXPORT void autoscroll_func()
{
    autoscroll = !autoscroll;
}

/*FUNCTION NAME :all_filter
 *ARGUMENTS     :void
 *RETURN TYPE   :void
 *DESCRIPTION   :setting the "filter string" to capture all packets
 */
void all_filter()
{
    
    gtk_entry_set_text((GtkEntry *)entry_port,"");
    gtk_entry_set_text((GtkEntry *)entry_addr,"");
    gtk_combo_box_set_active((GtkComboBox *)combo_box_proto,12);

    filter("");
}

/*FUNCTION NAME :interfaceDisp
 *ARGUMENTS     :GtkWidget *
 *RETURN TYPE   :void 
 *DESCRIPTION   :providing a list of interfaces available in the system using pcap lib function : pcap_findallde
vs */
void interfaceDisp(GtkWidget *box)
{

    pcap_if_t *ptlistAlldevs = NULL;
    int ipcapFinddevStatus = 0;
    GtkListStore *list;
    GtkTreeIter iter;
    GtkComboBox *combo_box_inter;

//providing the list of interfaces available in the system to user
    ipcapFinddevStatus = pcap_findalldevs(&ptlistAlldevs ,strErrbuf);
    if(ipcapFinddevStatus != 0)
    {
        printf("\nERROR :Finding interface devices to capture :%s\n",
            strErrbuf);
        exit(0);
    }  

    combo_box_inter = (GtkComboBox *) box;
    list = gtk_list_store_new(1,G_TYPE_STRING);  
    gtk_combo_box_set_model(combo_box_inter,(GtkTreeModel *)list);
    
    while(ptlistAlldevs != NULL)
    {   
        if((strcmp(ptlistAlldevs->name, "any")) == 0)
        {
   
        }
        else
        {         
            gtk_list_store_append(list,&iter);   
            gtk_list_store_set(list,&iter,0,ptlistAlldevs->name,-1);
        }
        ptlistAlldevs = ptlistAlldevs->next;
    }  
    
}

/*FUNCTION NAME :callback
 *ARGUMENTS     :u_char *args, const struct pcap_pkthdr* st_Pkthdr & const u_char* ac_Packet
 *RETURN TYPE   :void 
 *DESCRIPTION   :post the packet along with the time stamp into the global buffer
 */
void callback(u_char *args, const struct pcap_pkthdr* st_Pkthdr,
    const u_char* ac_Packet)
{
    unsigned long int cnt1 = 0;
	int len = 0;
    int *plen = &len;
    struct tm *tm;
    unsigned char app[50]="\0";
    time_t pkt_time;
    int n = 0;
	
	pkt_len1 = st_Pkthdr->caplen;
    pkt_time = st_Pkthdr->ts.tv_sec;
	tm = localtime(&pkt_time);

    snprintf((char *)app,30," %d/%d %d:%02d:%02d:%d",(int)tm->tm_mday,(int)(tm->tm_mon+1),
        (int) tm->tm_hour ,(int)tm->tm_min ,(int)tm->tm_sec ,(int)st_Pkthdr->ts.tv_usec);

	len = strlen((char *)app);
    memcpy(final, plen, 4);
    snprintf((char *)final+4, strlen((char *)app), (char *)app);

    n = strlen((char *)app);
    memcpy(final+n+4 ,ac_Packet ,st_Pkthdr->caplen);
	display_pkt();
}

/*FUNCTION NAME :statistics
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :print all the statistics information(no of packets for a particular kind of protocol)
 about the live capture
 */
void statistics()
{

    GtkWidget *text_view;
    GtkBuilder *builderstats;
    GError *error = NULL;
    GtkTextBuffer *bufferstats;
    GtkTextIter iterstats;
    builderstats = gtk_builder_new();

    if(stat_fl == 1)
    {
        gtk_widget_destroy(win_stats);
    } 
  
    if(!gtk_builder_add_from_file( builderstats, "pkt.glade", &error ) )
    {
        g_warning( "%s\n", error->message );
        g_free( error );
        exit(0);               
    }
    stat_fl = 1; 
  
    win_stats = GTK_WIDGET( gtk_builder_get_object( builderstats, "window2" ) ); 
    text_view = GTK_WIDGET( gtk_builder_get_object( builderstats, "textview3" ));

    bufferstats = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_view));
    gtk_text_buffer_get_iter_at_offset(bufferstats, &iterstats, 0);
    gtk_widget_show(win_stats); 
    gtk_widget_show(text_view);
    
    str_buff = "\nTOTAL NO OF PACKETS          :";
    gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
    sprintf(str, "%d", pkt_no);
    gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

//printing all the statistics counters for various protocols in file and some information regarding packets in the gui window (textviews of hbox1)
    if(inter_flag == 1)
    {
        str_buff = "\n\nNETWORK LAYER PROTOCOL";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));

        str_buff = "\nARP PACKETS                  :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", arp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nIPv4 PACKETS                 :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", ip4_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nIPv6 PACKETS                 :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", ip6_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nICMP PACKETS                :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", icmp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nIGMP PACKETS                :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", igmp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nOTHER PACKETS             :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", others_nwl_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\t  (RARP,PPP,PPPoE,etc)";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
    
        str_buff = "\n\nTRANSPORT LAYER PROTOCOL";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));

        str_buff = "\nTCP PACKETS                  :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", tcp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nUDP PACKETS                 :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", udp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nOTHER PACKETS             :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", others_tl_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\t  (EGP,SCTP,etc)";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));

        str_buff = "\n\nAPPLICATION LAYER PROTOCOL";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));

        str_buff = "\nHTTP PACKETS                  :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", http_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nDHCP PACKETS                 :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", dhcp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nDNS PACKETS                   :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", dns_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nFTP PACKETS                    :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", ftp_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));

        str_buff = "\nOTHER PACKETS               :";
        gtk_text_buffer_insert (bufferstats, &iterstats,str_buff, strlen(str_buff));
        sprintf(str, "%d", others_al_no);
        gtk_text_buffer_insert (bufferstats, &iterstats,str, strlen(str));
    }   

}

/*FUNCTION NAME :reset
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :reset all the counters pertaining to all the protocols in check and clear the log file & all the buffers in the textviews of hbox1
 */
void reset()
{
    pkt_no  = 0;
    arp_no = 0;
    ip4_no = 0;
    ip6_no = 0;
    icmp_no = 0;
    igmp_no = 0;
    tcp_no = 0;
    udp_no = 0;
    http_no = 0;
    dns_no = 0;
    ftp_no = 0;
    dhcp_no = 0;
    others_nwl_no = 0;
    others_tl_no = 0;
    others_al_no = 0;

    flush_buffer();
    flush_file();
    str_buff = "\nLOG FILE(PacketAnalyst.txt) and STATISTICS have been cleared";
    gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));

}

/*FUNCTION NAME :logfile
 *ARGUMENTS     :void *
 *RETURN TYPE   :void *
 *DESCRIPTION   :thread for opening logfile in notepad
 */
void *logfile(void *arg)
{
    system("notepad PacketAnalyst.txt");
    return NULL;
}

/*FUNCTION NAME :fileopen
 *ARGUMENTS     :void 
 *RETURN TYPE   :void 
 *DESCRIPTION   :creates logfile thread 
 */
void fileopen()
{

    iThread3Status = pthread_create(&threadid3 ,NULL ,logfile ,NULL);
    if(iThread3Status != 0)
    {
        str_buff = "\nERROR LOG FILE(packetanalyst.txt) could not be created";
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
        strcpy(str_buff ,strerror(errno));
        gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
    }  

}

/*FUNCTION NAME :capture
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :it is a thread for all operations relating to getting the packets from the interface namely, 
creating handle for interface ,setting NIC into promiscous mode & starting the live capture
 */
void* capture(void *arg)
{
   //creating the handle for the selected interface    
    
	Interhandle = pcap_open_live(intername,MAXMSGSIZE,1,1000,strErrbuf);
	
	if(Interhandle == NULL)
	{
		printf("\nERROR :Capture handle for the %s could not be created %s" ,
               intername,strErrbuf);
        exit(0);
    }
    breakflag = 1;
    flush_buffer();
//starting the live capture for the interface handle
    pcap_loop(Interhandle , -1 , callback , NULL);
	return NULL;
}

/*FUNCTION NAME :interSelect
 *ARGUMENTS     :GtkComboBox *
 *RETURN TYPE   :int
 *DESCRIPTION   :getting the interface from the user from combo box of gui using
 function :gtk_combo_box_get_active_text , starting the capture thread for the
 selected interface and used for changing the interface
 */
int interSelect(GtkComboBox *inter_box)
{
    int iThread1Status = VALOTHERTHANZERO;
    char temp[4] = {'\0'};
	struct pcap_if *d = NULL;

//getting the input from the user for selecting an interface
    intername = gtk_combo_box_get_active_text(inter_box); 
    if((strcmp(intername,"\0")) == 0)
    {
       str_buff = "\nSelect an Interface";
       gtk_text_buffer_insert (buffer, &iter,str_buff, strlen(str_buff));
       return 0;
	}
	
/* here we check if the live capture for any interface is already running
 * (i.e if the capture thread is already started) , if so we cancel the capture
 *  for that interface and restart the capture thread for the new interface
 *  selected*/
	inter_flag = 1;
    if(breakflag == 1)
    {
        if(pthread_cancel(threadid1) != 0)
        {
         exit (0);
        }
//resetting the logfile and statistics counters for the new capture
        reset();
        gtk_entry_set_text((GtkEntry *)entry_port,"");
        gtk_entry_set_text((GtkEntry *)entry_addr,"");
        gtk_combo_box_set_active((GtkComboBox *)combo_box_proto,12);
    }

    iThread1Status = pthread_create(&threadid1 ,NULL ,capture ,NULL);
    if(iThread1Status != 0)
    {
        printf("\nERROR :THREAD CREATE:%s",strerror(errno));
        exit(0);
    }
    return 0;
     
}

/*FUNCTION NAME :uninit
 *ARGUMENTS     :void
 *RETURN TYPE   :void 
 *DESCRIPTION   :thread cancellations, semaphore & logfile 
 */
void uninit()
{
    int iFileStatus = VALOTHERTHANZERO;
//cancelling all the threads
    if(breakflag == 1)
    {
        pthread_cancel(threadid1);
    }
    pthread_cancel(threadid2);

//closing the file
    iFileStatus = fclose(fp);
    if(iFileStatus == FILECLOSEERROR)
    {
        printf("\nERROR :in file close : %s \n",strerror(errno));
    }

    if(iThread3Status == 0)
    {
        pthread_cancel(threadid3);
    }

    gtk_main_quit();

    printf("\nThank you for using Packet Analyst :)\n");
}
  
G_MODULE_EXPORT void scroll()
{
     
      if(autoscroll == 1)
      { 
         adjustment = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scrolledwindow1));
         gtk_adjustment_set_value(adjustment,(gtk_adjustment_get_upper(adjustment) - gtk_adjustment_get_page_size(adjustment)));
      }
}

G_MODULE_EXPORT void scroll1()
{
     
         adjustment1 = gtk_scrolled_window_get_vadjustment(GTK_SCROLLED_WINDOW(scrolledwindow3));
         gtk_adjustment_set_value(adjustment1,(gtk_adjustment_get_upper(adjustment1) - gtk_adjustment_get_page_size(adjustment1)));
}


/*FUNCTION NAME :main
 *ARGUMENTS     :void
 *RETURN TYPE   :int 
 *DESCRIPTION   :Starts the display thread, 
 */
int main(int argc, char** argv)
{
    
    GtkBuilder *builder;
    GtkWidget *window;
    GError *error = NULL;
    GtkWidget *box;
    GtkWidget *vsp1;
    GtkWidget *vsp2;
    GtkWidget *vsp3;
    GtkWidget *vsp4;
    GtkWidget *vsp5;
    GtkWidget *vsp6;
    GtkWidget *vsp7;
    GtkWidget *vsp8;
    GtkWidget *vsp9;
    GtkWidget *vsp10;
    GtkWidget *vsp11;
    GtkWidget *vsp12;
    GtkWidget *vsp13;
    GtkWidget *vsp14;
    GtkWidget *vsp15;
    GtkWidget *vsp16;
    GtkWidget *hsp1;
   
    GtkWidget *button1;
    GtkWidget *button2;
    GtkWidget *button3;
    GtkWidget *button4;
    GtkWidget *button5;
    GtkWidget *button6;
    GtkWidget *button7;
    GtkWidget *button8;
    GtkWidget *button9;

    GtkWidget *viewport;
    GtkWidget *viewport2;
	GtkWidget * hbox ;
	GdkColor color;
//initialisation of thread safe mechanism for gtk 
	
    g_thread_init(NULL);
	gdk_threads_init();
//initialisation of gtk gui
    gtk_init( &argc, &argv );
    gdk_init( &argc, &argv );
//creating a reference for gtk builder
    builder = gtk_builder_new();
//adding front end glade file with the application
    if( ! gtk_builder_add_from_file( builder, "pkt.glade", &error ) )
    {
        g_warning( "%s\n", error->message );
        g_free( error );
        return( 1 );
    }

//getting references for all gtk widgets of the glade file in c code
    window = GTK_WIDGET( gtk_builder_get_object( builder, "window1" ) );
    box = GTK_WIDGET(gtk_builder_get_object( builder, "comboboxentry1" ));
    combo_box_proto = GTK_WIDGET(gtk_builder_get_object( builder, "comboboxentry2" ));
    entry_port = GTK_WIDGET(gtk_builder_get_object( builder, "entry1" ));
    entry_addr = GTK_WIDGET(gtk_builder_get_object( builder, "entry2" ));
    text_status = GTK_WIDGET( gtk_builder_get_object( builder, "textview1" ) );
 
    text_pktno = GTK_WIDGET( gtk_builder_get_object( builder, "text_pktno" ) ); 
    text_ts = GTK_WIDGET( gtk_builder_get_object( builder, "text_ts" ) ); 
    text_src = GTK_WIDGET( gtk_builder_get_object( builder, "text_src" ) ); 
    text_dst = GTK_WIDGET( gtk_builder_get_object( builder, "text_dst" ) ); 
    text_nwp = GTK_WIDGET( gtk_builder_get_object( builder, "text_nwp" ) ); 
    text_tlp = GTK_WIDGET( gtk_builder_get_object( builder, "text_tlp" ) ); 
    text_srcport = GTK_WIDGET( gtk_builder_get_object( builder, "text_srcport" ) ); 
    text_dstport = GTK_WIDGET( gtk_builder_get_object( builder, "text_dstport" ) ); 
    text_alp = GTK_WIDGET( gtk_builder_get_object( builder, "text_alp" ) );  

    scrolledwindow1 = GTK_WIDGET( gtk_builder_get_object( builder, "scrolledwindow1" ) );
    adjustment = GTK_ADJUSTMENT(( gtk_builder_get_object( builder, "adjustment1" ) ));

    scrolledwindow3 = GTK_WIDGET( gtk_builder_get_object( builder, "scrolledwindow3" ) );
    adjustment1 = GTK_ADJUSTMENT(( gtk_builder_get_object( builder, "adjustment2" ) ));

    viewport = GTK_WIDGET( gtk_builder_get_object( builder, "viewport1" ) );
    viewport2 = GTK_WIDGET( gtk_builder_get_object( builder, "viewport2" ) );

    button1 = GTK_WIDGET( gtk_builder_get_object( builder, "button1" ) );   
    button2 = GTK_WIDGET( gtk_builder_get_object( builder, "button2" ) );   
    button3 = GTK_WIDGET( gtk_builder_get_object( builder, "button3" ) );   
    button4 = GTK_WIDGET( gtk_builder_get_object( builder, "button4" ) );   
    button5 = GTK_WIDGET( gtk_builder_get_object( builder, "button5" ) );   
    button6 = GTK_WIDGET( gtk_builder_get_object( builder, "button6" ) );   
    button7 = GTK_WIDGET( gtk_builder_get_object( builder, "button7" ) );   
    button8 = GTK_WIDGET( gtk_builder_get_object( builder, "button8" ) );   
    button9 = GTK_WIDGET( gtk_builder_get_object( builder, "button9" ) );   

    vsp1 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator1" ) );   
    vsp2 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator2") );
    vsp3 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator3" ) );   
    vsp4 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator4" ) );   
    vsp5 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator5" ) );   
    vsp6 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator6") );
    vsp7 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator7") );
    vsp8 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator8") );
    vsp9 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator9") );
    vsp10 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator10") );
    vsp11 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator11") );
    vsp12 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator12") );
    vsp13 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator13") );
    vsp14 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator14") );
    vsp15 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator15") );
    vsp16 = GTK_WIDGET( gtk_builder_get_object( builder, "vseparator16") );
    hsp1 = GTK_WIDGET( gtk_builder_get_object( builder, "hseparator1") );

    hbox = GTK_WIDGET( gtk_builder_get_object( builder, "hbox1" ) );
	    
    gdk_color_parse("sky blue",&color);
    gtk_widget_modify_base(text_pktno,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_ts,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_nwp,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_src,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_dst,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_tlp,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_srcport,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_dstport,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_alp,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_base(text_alp,GTK_STATE_NORMAL,&color);
 
    gdk_color_parse("light yellow",&color);
    gtk_widget_modify_base(text_status,GTK_STATE_NORMAL,&color);

    gdk_color_parse("light grey",&color);
    gtk_widget_modify_bg(button1,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button2,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button3,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button4,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button5,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button6,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button7,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button8,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(button9,GTK_STATE_NORMAL,&color);

    gdk_color_parse("black",&color);
    gtk_widget_modify_bg(vsp1,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp2,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp3,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp4,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp5,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp6,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp7,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp8,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp9,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp10,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp11,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp12,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp13,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp14,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp15,GTK_STATE_NORMAL,&color);
    gtk_widget_modify_bg(vsp16,GTK_STATE_NORMAL,&color);

    gtk_widget_modify_bg(hsp1,GTK_STATE_NORMAL,&color);

    gtk_widget_modify_bg(viewport,GTK_STATE_NORMAL,&color);
    
    gtk_widget_modify_bg(viewport2,GTK_STATE_NORMAL,&color);
      
    gdk_color_parse("white",&color);
    gtk_widget_modify_bg(window,GTK_STATE_NORMAL,&color);
    
/*initialising global variables ,creating GtkWidgets &logfile 
using init()*/
    init();

//connecting the handler functions with respective buttons on gui 
    gtk_builder_connect_signals( builder, NULL );
    g_object_unref( G_OBJECT( builder ) );
    gtk_widget_show( window );
//building the dynamic list for interfaces drop down box in gui 
    interfaceDisp(box);
    gdk_threads_enter();
    gtk_main();
    gdk_threads_leave();
    return 0;
}
