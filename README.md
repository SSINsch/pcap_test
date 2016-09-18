# pcap_test

————————————————————————————————————

pcap_test
============
check if ethernet / ip / tcp.
if so, print it.
the program will print the information about the packet, only if it has ethernet->ip->tcp.


+ Ethernet header -> dst_mac / src_mac
+ ip header -> src_ip / dst_ip
+ tcp header -> src_port / dst_port
+ print Data
+ ????
+ ##PROFIT!


struct tcphdr
{
    u_int16_t th_sport;     // source port
    u_int16_t th_dport;     // destination port
    tcp_seq th_seq;    		// sequence number
    tcp_seq th_ack;     	// acknowledgement number
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    u_int8_t th_x2:4;       // (unused)
    u_int8_t th_off:4;      // data offset
#  endif
#  if __BYTE_ORDER == __BIG_ENDIAN
    u_int8_t th_off:4;      // data offset
    u_int8_t th_x2:4;       // (unused)
#  endif
    u_int8_t th_flags;
#  define TH_FIN    0x01
#  define TH_SYN    0x02
#  define TH_RST    0x04
#  define TH_PUSH   0x08
#  define TH_ACK    0x10
#  define TH_URG    0x20
    u_int16_t th_win;       // window
    u_int16_t th_sum;       // checksum
    u_int16_t th_urp;       // urgent pointer
};

struct ip
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;       // header length
    unsigned int ip_v:4;        // version
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;        // version
    unsigned int ip_hl:4;       // header length
#endif
    u_int8_t ip_tos;            // type of service
    u_short ip_len;         	// total length
    u_short ip_id;          	// identification
    u_short ip_off;         	// fragment offset field
#define IP_RF 0x8000            // reserved fragment flag
#define IP_DF 0x4000            // dont fragment flag
#define IP_MF 0x2000            // more fragments flag
#define IP_OFFMASK 0x1fff       // mask for fragmenting bits
    u_int8_t ip_ttl;            // time to live
    u_int8_t ip_p;          	// protocol
    u_short ip_sum;         	// checksum
    struct in_addr ip_src, ip_dst;  // source and dest address
};

struct ethhdr
{
    unsigned char   h_dest[ETH_ALEN];   // destination eth addr
    unsigned char   h_source[ETH_ALEN]; // source ether addr
    unsigned short  h_proto;            // packet type ID field
};


——————————————————————————————————————-
