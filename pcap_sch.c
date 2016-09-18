#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define ERRBUF_SIZE			100
#define PACKET_MAX_BYTES	300
#define PROMISCUOUS_MODE	1
#define NON_PROMISCUOUS		0
#define WAIT_MAX_TIME		1000

struct ip *iph;				// IP header struct
struct tcphdr *tcph;		// TCP header struct
struct ether_header *eth;	// ethernet header struct
int count;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

int main(int argc, char *argv[])
{
	char 			*device;					// device name
	char 			errorbuffer[ERRBUF_SIZE];	// Error string
	bpf_u_int32		mask = 0;					// mask information
	bpf_u_int32		net = 0;					// IP information
	pcap_t 			*pcd;					// packet descriptor
	struct in_addr	net_addr;				// address of ip
	struct in_addr	mask_addr;				// address of mask
	const u_char *packet;					// packet

	// program format
	if(argc != 2 || argc != 1){
		printf("---PROGRAM FORMAT---\n");
		printf("%s [number_of_pakcet]\n", argv[0]);
	}
	if(argc == 1)
		argv[1] = "0";

	// find the device
	device = pcap_lookupdev(errorbuffer);
	if (device == NULL) {
		printf("No devices: %s\n", errorbuffer);
		return 0;
	}
	else
		printf("device: %s\n", device);

        // convert the information to look good 
	net_addr.s_addr = net;
	 if(inet_ntoa(net_addr) == NULL) {
        printf("Cannot convert >> net_addr");
        return 0;
	}
	printf("NET : %s\n", inet_ntoa(net_addr));
	mask_addr.s_addr = mask;
	printf("MSK : %s\n", inet_ntoa(mask_addr));
	printf("--------------------------------\n");

	// get device information
	if(pcap_lookupnet(device, &net, &mask, errorbuffer) == -1)
		printf("Cannot get information of devce %s: %s\n", device, errorbuffer);

	// open the device
	pcd = pcap_open_live(device, PACKET_MAX_BYTES, PROMISCUOUS_MODE, WAIT_MAX_TIME, errorbuffer);
	if(pcd == NULL){
		printf("Cannot open device %s: %s\n", device, errorbuffer);
		return 0;
	}

	// get the packet
	pcap_loop(pcd, atoi(argv[1]), callback, NULL);

	pcap_close(pcd);

	return 1;
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	// get ehternet header 
    eth = (struct ether_header *)packet;

    // get IP header   
    packet = packet + sizeof(struct ether_header);

    printf("=============== %04d ===============\n", count);
    count++;

    // if ip
    if(ntohs(eth->ether_type) == ETHERTYPE_IP){
    	iph = (struct ip *) packet;
    	// if TCP
    	if (iph->ip_p == IPPROTO_TCP)
        {
        	printf("Source MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
        	printf("Desitnation MAC : %02X:%02X:%02X:%02X:%02X:%02X\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

        	printf("Version     : %d\n", iph->ip_v);
        	printf("Header Len  : %d\n", iph->ip_hl);
        	printf("source Address      : %s\n", inet_ntoa(iph->ip_src));
        	printf("Destination Address : %s\n", inet_ntoa(iph->ip_dst));
            
            tcph = (struct tcp *)(packet + iph->ip_hl * 4);
            printf("Source port      : %d\n" , ntohs(tcph->source));
            printf("Destination Port : %d\n" , ntohs(tcph->dest));
        }
    }
    else{
    	printf("[No IP packet]");
    }
    printf("\n\n");
}
