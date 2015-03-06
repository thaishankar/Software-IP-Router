#include "header.h"

/*Init function for pcap - Sets eth frame, IP header and creates a handle*/
pcap_t* pcap_init(char *dev)
{
	int index = atoi(dev+3);
	char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
	char filter_exp[100];// = "ip and ether dst ";	/* filter expression [3] */
	
	//"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" , infMac[0], infMac[1], infMac[2], infMac[3], infMac[4], infMac[5] 
	//if(index == 0)
		//sprintf(filter_exp,"ip and src host 10.1.2.3 and ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",sArray[index].ether_shost[0],sArray[index].ether_shost[1],sArray[index].ether_shost[2],sArray[index].ether_shost[3],sArray[index].ether_shost[4],sArray[index].ether_shost[5]);
	//if(index == 1)
	sprintf(filter_exp,"ip and ether dst %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",sArray[index].ether_shost[0],sArray[index].ether_shost[1],sArray[index].ether_shost[2],sArray[index].ether_shost[3],sArray[index].ether_shost[4],sArray[index].ether_shost[5]);
	fprintf(stdout,"exp: %s",filter_exp);
	struct bpf_program fp;                  /* compiled filter program (expression) */
	bpf_u_int32 mask;                       /* subnet mask */
	bpf_u_int32 net;                        /* ip */
	
	
	/* find a capture device if not specified on command-line */
	//	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
		exit(EXIT_FAILURE);
	}
	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",dev, errbuf);
		net = 0;
		mask = 0;
	}
	
	/* print capture info */
	//printf("Device: %s\n", dev);
	//printf("Filter expression: %s\n", filter_exp);
	
	/* open capture device */
	pcap_t *handle = pcap_open_live(dev, SNAP_LEN, 0, 0, errbuf);
	if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			exit(EXIT_FAILURE);
	}
	
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
	}
	
	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	
	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
				filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
	}
	return handle;
}


pcap_t* pcap_inject_init(char *dev)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0]='\0';
	pcap_t* pcap=pcap_open_live(dev,SNAP_LEN,1,0,pcap_errbuf);
	if (pcap_errbuf[0]!='\0') {
		fprintf(stderr,"%s",pcap_errbuf);
	}
	if (!pcap) {
		exit(1);
	}
	return pcap;
}
	
void getsrcIpMac(char *dev,char* cpy,struct in_addr *ipsrc)
{
	int fd;
    struct ifreq ifr;
    char *iface = dev;
    unsigned char *mac;
     
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	
	ioctl(fd,SIOCGIFADDR,&ifr);
	struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(ipsrc,&source_ip_addr->sin_addr.s_addr,sizeof(struct in_addr));
    
	
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	memcpy(cpy, mac, ETHER_ADDR_LEN);
	//printf("Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	//printf("cpy Mac : %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , cpy[0], cpy[1], cpy[2], cpy[3], cpy[4], cpy[5]);
	return;
}	

uint16_t chksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    size_t i;
	for (i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

