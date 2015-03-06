#include "header.h"

void insert_table(RTable_t *entry)
{
	if((head == NULL) || (head->netmask.s_addr <= entry->netmask.s_addr))
	{
		entry->next=head;
		head=entry;
		return;
	}
	RTable_t* temp=head->next;
	RTable_t* prev = head;
	while(temp)
	{
		if(temp->netmask.s_addr <= entry->netmask.s_addr)
		{
			entry->next = temp;
			prev->next = entry;
			return;			
		}
		prev = temp;
		temp = temp->next;

	}
	/*iterated over entire list*/
	prev->next = entry;
	entry->next = NULL;
	return ;
}

void delete_table(RTable_t *entry)
{
	if((entry->dst_net.s_addr==head->dst_net.s_addr)&&(entry->netmask.s_addr == head->netmask.s_addr))
	{
		RTable_t* del_node=head;
		head=head->next;
		free(del_node);
		return;
	}
	RTable_t *nxt=head->next;
	RTable_t* prev = head;
	while(nxt!=NULL)
	{
		if((nxt->dst_net.s_addr == entry->dst_net.s_addr)&&(nxt->netmask.s_addr==entry->netmask.s_addr))
		{
			prev->next = nxt->next;
			//RTable_t *del_node=prev->next;
			//prev->next=prev->next->next;
			free(nxt);	
			nxt = NULL;
			break;
		}
		prev = nxt;	
		nxt = nxt->next;
		
	}
}

void print_table()
{
	RTable_t *temp;
	if(head==NULL)
		return;
	temp=head;
	while(temp!=NULL)
	{
		char *addr1;
		char *addr2;
		addr1=inet_ntoa(temp->dst_net);
		addr2=inet_ntoa(temp->netmask);
		printf("Dest: %s ",inet_ntoa(temp->dst_net));
		printf("mask: %s  ",inet_ntoa(temp->netmask));
		printf("hop: %s ", inet_ntoa(temp->next_hop));
		printf("intf: %s ", temp->intf);
		/*unsigned long network=temp->dst_net.s_addr & temp->netmask.s_addr;
		struct in_addr net;
		net.s_addr=network;
		printf("Net ID :");
		printf("%s \n",inet_ntoa(net));*/
		
		printf("\n");
		
		temp=temp->next;
	}
}

void route(struct in_addr dst_ip, route_result_t *res)
{
	RTable_t* tmp = head;
	while((tmp!=NULL))
	{
		if((tmp->netmask.s_addr & dst_ip.s_addr) == tmp->dst_net.s_addr)
		{
			#ifdef LOG 
			printf("Inf : %s", tmp->intf);
			#endif
			res->egress_intf = tmp->intf;
			res->next_hop = tmp->next_hop;
			return;
		}
		tmp = tmp->next;
	}	 
	res->egress_intf='\0';
	return;
}

void create_table()
{
	FILE *fp=fopen("routing_table.txt","r");
	char buf[100];
	while(fgets(buf,sizeof(buf),fp)!=NULL)
	{
		char temp1[50],temp2[50],temp3[50];
		RTable_t* entry=(RTable_t*)malloc(sizeof(RTable_t));
		memset(entry,0,sizeof(RTable_t));
		
		sscanf(buf,"%s %s %s %s",temp1,temp2,temp3,entry->intf);
		inet_aton(temp1,&(entry->netmask));
		inet_aton(temp2,&(entry->dst_net));
		inet_aton(temp3,&(entry->next_hop));		

		insert_table(entry);
	}
	#ifdef LOG 
	printf("*************************\n");
	print_table();
	#endif
	/*struct in_addr ip;
	inet_aton("10.1.0.2",&ip);
	route(ip);
	*/
	
}

char* search_ARP_table(struct in_addr search_ARP)
{
	int i;
	for(i=0;i<ARPHead;i++)
	{
		if(arp_table[i].dst_ip.s_addr == search_ARP.s_addr)
			return arp_table[i].mac_addr;
	}
	return NULL;
	
}

void create_ARP_table()
{
	FILE *fp=fopen("./arptable.txt","r");
	char buf[300];
	fgets(buf,sizeof(buf),fp);
	printf("ARP TAble Entries \n");
	while(fgets(buf,sizeof(buf),fp)!=NULL)
	{
		char temp1[50],temp2[50],temp3[50],temp4[50],temp5[50],temp6[50];
		ARPTable_t* entry=(ARPTable_t*)malloc(sizeof(ARPTable_t));
		memset(entry,0,sizeof(ARPTable_t));
		
		sscanf(buf,"%s\t%s\t%s\t%s\t%s\t%s",temp1,temp2,temp3,temp4,temp5,temp6);
		inet_aton(temp1,&(arp_table[ARPHead].dst_ip));	
		
		unsigned int iMac[6];
		unsigned char mac[6];
		int i;

		sscanf(temp4, "%x:%x:%x:%x:%x:%x", &iMac[0], &iMac[1], &iMac[2], &iMac[3], &iMac[4], &iMac[5]);
		for(i=0;i<ETHER_ADDR_LEN;i++)
			arp_table[ARPHead].mac_addr[i] = (unsigned char)iMac[i];
			
		
		printf("%s \t %s \t %s \t %s \t %s \t %s\n",temp1,temp2,temp3,arp_table[ARPHead].mac_addr,temp5,temp6);
		printf("hop: %s \n\n", inet_ntoa(arp_table[ARPHead].dst_ip));
		
		
		ARPHead++;
	}
	/*struct in_addr search_ARP;
	inet_aton("192.168.1.254",&search_ARP);
	char *result=search_ARP_table(search_ARP);*/
	//printf("ARP result = %s\n",result);
}


