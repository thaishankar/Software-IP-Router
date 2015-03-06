#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h> 
#include <sys/time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include"asm/types.h"
#include"asm/types.h"


#define MAX_PAYLOAD_SIZE 1480
#define MAX_ALLOWED_PACKETS 1024*256
#define MAX_NUM_OF_INTERFACES 10
#define TABLE_SIZE 100
#define DYNAMIC 0 

/* IP header */
typedef struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
}sniff_ip;
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct sniff_icmp{
	u_char type;
	u_char code;
	u_short icmp_sum;
	u_short id;
	u_short seq_num;
};

typedef struct RTable
{
	struct in_addr dst_net;
	struct in_addr netmask;
	struct in_addr next_hop;
	unsigned char intf[10];
	struct RTable *next;
}RTable_t;

typedef struct snd{
	char name[5];
	pcap_t *sndHandle;
	u_char ether_shost[ETHER_ADDR_LEN];
	struct in_addr ip_src;
	}sndArray_t;

typedef struct ARPTable
{
	struct in_addr dst_ip;
	u_char  mac_addr[ETHER_ADDR_LEN];    /* source host address */
}ARPTable_t;

typedef struct route_result{
	char *egress_intf;
	struct in_addr next_hop;
}route_result_t;

extern RTable_t* head;	
extern int ARPHead;
extern ARPTable_t arp_table[TABLE_SIZE];
extern sndArray_t sArray[10];

#ifdef DYNAMIC
pthread_mutex_t intf_lock[10];
#endif

#define ERR_RET(x) do { perror(x); return EXIT_FAILURE; } while (0);
#define BUFFER_SIZE 4095
