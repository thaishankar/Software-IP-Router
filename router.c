#include "header.h"
	
pcap_t *handle,*rhandle;                         /* packet capture handle */
struct ether_header header;
sndArray_t sArray[10];
sniff_ip iph;
char *dev;

RTable_t table[TABLE_SIZE];
ARPTable_t arp_table[TABLE_SIZE];
RTable_t* head=NULL; /*This points to the Routing table*/
int ARPHead=0;

int ifname(int if_index,char *ifName)
{
	int fd,retVal = -1;
	struct sockaddr_in *sin;
	struct ifreq ifr;
	
	
	fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(fd == -1)
	{
	perror("socket");
	exit(1);
	}
	
	ifr.ifr_ifindex = if_index;
	
	if(ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr)))
	{
	perror("ioctl");
	exit(1);
	}
    if(strlen(ifr.ifr_name) < 10) 	
		strncpy(ifName, ifr.ifr_name,strlen(ifr.ifr_name));
		ifName[strlen(ifr.ifr_name)]='\0';
	return ;
}

int  loop (int sock, struct sockaddr_nl *addr)
{
    int     received_bytes = 0;
	unsigned long gateWay;
	unsigned long mask;
    struct  nlmsghdr *nlh;
	char 	MaskNet[32];
    char    destination_address[32];
    char    gateway_address[32];
    struct  rtmsg *route_entry;  /* This struct represent a route entry \
                                    in the routing table */
    struct  rtattr *route_attribute; /* This struct contain route \
                                            attributes (route type) */
    int     route_attribute_len = 0;
    char    buffer[BUFFER_SIZE];
	char interfaceName[10];

    bzero(destination_address, sizeof(destination_address));
    bzero(gateway_address, sizeof(gateway_address));
    bzero(buffer, sizeof(buffer));

    /* Receiving netlink socket data */
    while (1)
    {
        received_bytes = recv(sock, buffer, sizeof(buffer), 0);
        if (received_bytes < 0)
            ERR_RET("recv");
        /* cast the received buffer */
        nlh = (struct nlmsghdr *) buffer;
        /* If we received all data ---> break */
        if (nlh->nlmsg_type == NLMSG_DONE)
            break;
        /* We are just intrested in Routing information */
        if (addr->nl_groups == RTMGRP_IPV4_ROUTE)
            break;
    }

    /* Reading netlink socket data */
    /* Loop through all entries */
    /* For more informations on some functions :
     * http://www.kernel.org/doc/man-pages/online/pages/man3/netlink.3.html
     * http://www.kernel.org/doc/man-pages/online/pages/man7/rtnetlink.7.html
     */
      struct ifaddrmsg *rtmp;
	 rtmp = (struct ifaddrmsg *) NLMSG_DATA(nlh);
	 mask = rtmp->ifa_prefixlen;
	 
	 
    for ( ; NLMSG_OK(nlh, received_bytes); \
                    nlh = NLMSG_NEXT(nlh, received_bytes))
    {

        /* Get the route data */
        route_entry = (struct rtmsg *) NLMSG_DATA(nlh);

        /* We are just intrested in main routing table */
        if (route_entry->rtm_table != RT_TABLE_MAIN)
            continue;

        /* Get attributes of route_entry */
        route_attribute = (struct rtattr *) RTM_RTA(route_entry);

        /* Get the route atttibutes len */
        route_attribute_len = RTM_PAYLOAD(nlh);
        /* Loop through all attributes */
        for ( ; RTA_OK(route_attribute, route_attribute_len); \
            route_attribute = RTA_NEXT(route_attribute, route_attribute_len))
        {
            /* Get the destination address */
            if (route_attribute->rta_type == RTA_DST)
            {
				/*int count = 32 - route_entry->rtm_dst_len;
				mask = 0xffffffff;
				for (; count!=0 ;count--)
					mask = mask << 1;*/
                inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                        destination_address, sizeof(destination_address));
            }
            /* Get the gateway (Next hop) */
            if (route_attribute->rta_type == RTA_GATEWAY)
            {
				gateWay = *(unsigned long *) RTA_DATA(route_attribute);
                inet_ntop(AF_INET, RTA_DATA(route_attribute), \
                        gateway_address, sizeof(gateway_address));
            }
			/*Get interface*/
			if (route_attribute->rta_type == RTA_OIF)
			{
				ifname(*((int *) RTA_DATA(route_attribute)),interfaceName);
			
			}
			
        }

		uint32_t ms = route_entry->rtm_dst_len;
		ms = 32-ms;
		uint32_t ns = pow(2,ms) - 1;
		ns = ~ns;

		struct in_addr addr; // Holds the Netmask
		addr.s_addr = htonl(ns);
		printf("netmask : %s\n",inet_ntoa(addr));	
        /* Now we can dump the routing attributes */
		RTable_t *newlink;
		newlink = (RTable_t*)malloc(sizeof(RTable_t));
		inet_aton(destination_address,&newlink->dst_net);
		newlink->netmask.s_addr = addr.s_addr;
		inet_aton(gateway_address,&newlink->next_hop);
		strcpy(newlink->intf,&interfaceName); 
				
        if (nlh->nlmsg_type == RTM_DELROUTE)
		{
		
			int lock=0;
			for(lock=0;lock<10;lock++)
			{
				pthread_mutex_lock(&intf_lock[lock]);
			}
				delete_table(newlink);
			for(lock=0;lock<10;lock++)
			{
				pthread_mutex_unlock(&intf_lock[lock]);
			}
			
			printf("interface : %s\n", interfaceName); //Holds the interface name
			//printf("ms : %d\n", route_entry->rtm_dst_len); 
            fprintf(stdout, "Deleting route to destination nw --> %s and nxt hop %s\n", \
                destination_address, gateway_address);	
        }
		if (nlh->nlmsg_type == RTM_NEWROUTE)
		{
			int lock=0;
			for(lock=0;lock<10;lock++)
			{
				pthread_mutex_lock(&intf_lock[lock]);
			}
				insert_table(newlink);
			for(lock=0;lock<10;lock++)
			{
				pthread_mutex_unlock(&intf_lock[lock]);
			}
			//printf("mask : 0x%08x", mask);
			printf("interface : %s", interfaceName);
            printf("Adding route to destination --> %s and gateway %s\n ", \
                            destination_address, gateway_address);
		
		}
		print_table();
	}
	//newlink = NULL;
	
    return 0;
}

void *dThd()
{
	 int sock = -1;
    struct sockaddr_nl addr;

    /* Zeroing addr */
    bzero (&addr, sizeof(addr));

    if ((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0)
        ERR_RET("socket");

    addr.nl_family = AF_NETLINK;
    addr.nl_groups = RTMGRP_IPV4_ROUTE;

    if (bind(sock,(struct sockaddr *)&addr,sizeof(addr)) < 0)
        ERR_RET("bind");

    while (1)
        loop (sock, &addr);

    /* Close socket */
    close(sock);

    return 0;
}

void got_packet(struct pcap_pkthdr *header,const u_char *packet,char *dev,char *frame)
{
	char *dintf;
	struct sniff_ethernet ether;
	struct sniff_ip ipp;
	struct sniff_icmp icmp;
	
	int index = atoi(&dev[3]);
	struct sniff_ethernet *eth = (struct sniff_ethernet *)(packet);
	struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	struct sniff_icmp *icmpp = NULL;
	if(ip->ip_p == IPPROTO_ICMP)
		icmpp = (struct sniff_icmp *)(packet + SIZE_ETHERNET + sizeof(struct sniff_ip));
		
	ip->ip_ttl = ip->ip_ttl-1;
	if(ip->ip_ttl == 0)
	{
		//printf("Got ttl 0 packet\n");
		//SEND ICMP MESSAGE BACK TO SRC
		//int size_ip = IP_HL(ip)*4; //ip header size in bytes
		memcpy(&ether.ether_dhost,eth->ether_shost,ETHER_ADDR_LEN);
		/*printf("incoming eth->ether_shost %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
		int j=0;
		printf("setting ether.ether_dhost");
		for(j=0;j<=5;j++)
			printf("%.2x:",ether.ether_dhost[j]);
		printf("\n");*/
		//printf("eth->ether_shost %.2x:%.2x:%.2x:%.2x:%.2x:%.2x \n",ether.ether_dhost[0],ether.ether_dhost[1],ether.ether_dhost[2],ether.ether_dhost[3],ether.ether_dhost[4],ether.ether_dhost[5]);
		memcpy(&ether.ether_shost,eth->ether_dhost,ETHER_ADDR_LEN);
		/*printf("incoming eth->ether_dhost");
		for(j=0;j<=5;j++)
			printf("%.2x:",eth->ether_dhost[j]);
		printf("\n");
		
		printf("setting ether.ether_shost");
		for(j=0;j<=5;j++)
			printf("%.2x:",ether.ether_shost[j]);
		printf("\n");*/
		//printf("ether_shost %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ether.ether_shost[0],ether.ether_shost[1],ether.ether_shost[2],ether.ether_shost[3],ether.ether_shost[4],ether.ether_shost[5]);
		//printf("%s",ether.ether_shost);
		memcpy(&ether.ether_type,&(eth->ether_type),sizeof(u_short));
		//ether.ether_type = htons(0x0800);
		//printf("ETHER TYPE: %d \n",ether.ether_type);
		memcpy(&ipp.ip_src,&sArray[index].ip_src,4);
		memcpy(&ipp.ip_dst,&ip->ip_src,4);
				
		//populate ip header fields
		ipp.ip_vhl = 4;
		ipp.ip_vhl = ipp.ip_vhl << 4;
		ipp.ip_vhl = ipp.ip_vhl | 0x05;
		ipp.ip_tos = 0;
		ipp.ip_p = 1;
		ipp.ip_ttl = 64;
		ipp.ip_len = htons(76);//+ntohs(ip->ip_len);
		ipp.ip_id = ip->ip_id;
		ipp.ip_off = ip->ip_off;
		ipp.ip_sum = 0;
		ipp.ip_sum = chksum(&ipp,20); //ip header cksum
		
		//populate icmp header field
		icmp.type = 11;
		icmp.code = 0;
		memset(&icmp.id,0,2);
		memset(&icmp.seq_num,0,2);
		icmp.icmp_sum = 0;
				
		//Construct frame
		//char *frame = (char *)malloc(SIZE_ETHERNET+76);//+ntohs(ip->ip_len)); moved to intfThd function
		memset(frame,0,SIZE_ETHERNET+76);
		memcpy(frame,&ether,SIZE_ETHERNET);
		memcpy(frame+SIZE_ETHERNET,&ipp,sizeof(ipp));
		memcpy(frame+SIZE_ETHERNET+sizeof(ipp),&icmp,sizeof(icmp));	
		memcpy(frame+sizeof(ether)+sizeof(ipp)+sizeof(icmp),ip,48);

		icmp.icmp_sum = chksum(frame+34,56); // to calc icmp chksum	for icmp header and payload
		memcpy(frame+36,&icmp.icmp_sum,2);
		
		if (pcap_inject(sArray[index].sndHandle,frame,SIZE_ETHERNET+76)==-1)
		{
			pcap_perror(sArray[index].sndHandle,0);
			pcap_close(sArray[index].sndHandle);
			return;
		}	
		return;
	}
	
	if((ip->ip_dst.s_addr == sArray[index].ip_src.s_addr))
	{
		if(ip->ip_p == IPPROTO_ICMP)
		{
			memcpy(&ether.ether_dhost,eth->ether_shost,ETHER_ADDR_LEN);
			memcpy(&ether.ether_shost,eth->ether_dhost,ETHER_ADDR_LEN);
			memcpy(&ether.ether_type,&(eth->ether_type),sizeof(u_short));
			memcpy(&ipp.ip_src,&ip->ip_dst,4);
			memcpy(&ipp.ip_dst,&ip->ip_src,4);
			
			//edit ip header field
			ip->ip_ttl = 64;
			ip->ip_sum = 0;
			ip->ip_sum = chksum(ipp,20);
					
			//edit icmp header field
			icmpp->type = 0;
			icmpp->icmp_sum = 0;
			icmpp->icmp_sum = chksum(icmpp,htons(ip->ip_len)-20);
			//icmpp+htons(ip->ip_ len)+8 = "abcd123";
			
			if (pcap_inject(sArray[index].sndHandle,packet,SIZE_ETHERNET+htons(ip->ip_len))==-1)
			{
				pcap_perror(sArray[index].sndHandle,0);
				pcap_close(sArray[index].sndHandle);
				return;
			}		
		}	
		return;
	}	
		
	if(strcmp(eth->ether_dhost,sArray[index].ether_shost))
	{
		printf("SNIFFING OWN PACKET \n");
		return;
	}
	
	route_result_t res;
	
	pthread_mutex_lock(&intf_lock[index]);
	
	route(ip->ip_dst,&res); //got dest intf here
	
	pthread_mutex_unlock(&intf_lock[index]);
	
	if(res.egress_intf==NULL) //route not found; drop packet
		return; 
	int size_ip_header = IP_HL(ip)*4; //ip header size in bytes
	ip->ip_sum = htons(0);
	ip->ip_sum = chksum((void *)ip,size_ip_header);
	int egress = atoi(&res.egress_intf[3]);
	memcpy(eth->ether_shost,&sArray[egress].ether_shost,ETHER_ADDR_LEN); //copied src mac
	char *dst_mac = search_ARP_table(res.next_hop);
	if(dst_mac == NULL)
	{
		// decide to broadcast or drop packet
		return;
	}
	memcpy(eth->ether_dhost,dst_mac,ETHER_ADDR_LEN); //copied next_hop mac
	
	if (pcap_inject(sArray[egress].sndHandle,packet,SIZE_ETHERNET+ntohs(ip->ip_len))==-1)
	{
		pcap_perror(sArray[egress].sndHandle,0);
		pcap_close(sArray[egress].sndHandle);
		return;
	}
}


void * intfThd(void *name)
{
	name = (char *)name;
	
	
	
	
	pcap_t *rHandle = pcap_init(name);	
	printf("In thread %s\n", (char *)name);
	struct pcap_pkthdr header;
	const u_char *packet =NULL;		// The actual packet 
	char *frame = (char *)malloc(SIZE_ETHERNET+76);
	
	packet = pcap_next(rHandle,&header);
	while(1)
	{
		//if(strcmp(packet,""))
			got_packet(&header,packet,name,frame);
		//printf("Got packet on interface %s", name);
		packet = pcap_next(rHandle,&header);
		
	}
	free(frame);	
}	
	

int main(int argc, char* argv[])
{
	pthread_t pid[MAX_NUM_OF_INTERFACES];
	int lock=0;
	for(lock=0;lock<10;lock++)
		pthread_mutex_init(&intf_lock[lock],NULL);
		
	pcap_if_t *alldevsp;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/*Creating Routing tables. This populates the structure and updates head ptr*/
	create_table();
	create_ARP_table();
	
	int retval = pcap_findalldevs(&alldevsp,errbuf);
	if (retval == -1)
	{
		fprintf(stderr,"ERROR\n");
		exit(1);
	}
	int i =0;
	/*Creating send handles for all interfaces and stores both handles and their MACs in sArray*/
	pcap_if_t *temp = alldevsp; 
	while(temp)
	{
		if(strncmp(temp->name,"eth0",4) && strncmp(temp->name,"eth1",4) && strncmp(temp->name,"eth2",4) && strncmp(temp->name,"eth4",4))
		{
			temp=temp->next;
			continue;
		}
		/*Only eth devices*/
		
		int index = atoi(temp->name+3);
		strcpy(sArray[index].name,temp->name);//name
		sArray[index].sndHandle = pcap_inject_init(&sArray[index].name);//send handle
		unsigned char infMac[ETHER_ADDR_LEN];
		getsrcIpMac(&sArray[index].name,&sArray[index].ether_shost,&sArray[index].ip_src); // get src IP and MAC
		printf("Source IP for interface %s : %s\n",temp->name, inet_ntoa((sArray[index].ip_src)));
		#ifdef LOG 
		printf("infMac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , sArray[index].ether_shost[0], sArray[index].ether_shost[1], sArray[index].ether_shost[2], sArray[index].ether_shost[3], sArray[index].ether_shost[4], sArray[index].ether_shost[5]);	
		#endif
		//memcpy((sArray[index]).ether_shost,infMac,ETHER_ADDR_LEN); //src mac
		
		int err = pthread_create(&pid[i],NULL,&intfThd,(void*)&sArray[index].name);
		if(err !=0)
		{
			printf("Error in thread creation");
			exit(0);
		}
		temp=temp->next;
		i++;
	}
	/*Start the dynamic thread*/
	pid_t dynThd;
	int err = pthread_create(&dynThd,NULL,dThd,NULL);
	if(err !=0)
	{
		printf("Error in thread creation");
		exit(0);
	}
	
	while(1)
		sleep(20);
	//pthread_join(pid[0],NULL);
	return 0;
}
