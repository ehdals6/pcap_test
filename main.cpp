#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#define ETHER_LEN 14
#define ETHER_ADDR_LEN	6
#define ETHERTYPE_IP 0X0800
#define IPPROTO_TCP 0X06
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff	
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20	
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int hex_to_ip(unsigned int hex, char* ip_str)
{
  sprintf(ip_str, "%3d", (hex) & 0xff);
  ip_str[3] = '.';
  sprintf(ip_str+4, "%3d", (hex >> 8) & 0xff);
  ip_str[7] = '.';
  sprintf(ip_str+8, "%3d", (hex >> 16) & 0xff);
  ip_str[11] = '.';
  sprintf(ip_str+12, "%d", (hex >> 24) & 0xff);
  ip_str[15] = 0;
}
int printarr(unsigned char* arr, int length )
{
	int i;
	for (int i = 0; i < length; ++i)
	{
		printf("%2x ",arr[i]);
	}
	printf("\n");
	return 0;
}

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		uint32_t ip_src;
		uint32_t ip_dst;	 /* source and dest address */
	};


	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
		u_char th_flags;
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

int swap_word_endian(unsigned short swap)
{
	return (swap << 8 | swap >> 8);
}
int ip_check(unsigned short type)
{
	return type==ETHERTYPE_IP ? 1: 0 ;
}

int tcp_check(unsigned short protocol)
{
	return protocol==IPPROTO_TCP ? 1: 0;
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  //Default variables
  struct pcap_pkthdr* header;
  const u_char* packet;
  int res;

  // My variables , structures 
  struct sniff_ethernet *ethernet;
  struct sniff_ip *ip;
  struct sniff_tcp *tcp;
  u_int size_ip;
  u_int size_tcp;
  u_int size_data;
  u_char* data;
  char ip_src_str[16];    // readable ip 
  char ip_dst_str[16];    // readable ip

  while (true) {
    pcap_next_ex(handle, &header, &packet);
    ethernet = (struct sniff_ethernet*)packet;
    ip = (struct sniff_ip*)(packet+ETHER_LEN);
    size_ip = IP_HL(ip)*4; 
    tcp = (struct sniff_tcp*)(packet+ETHER_LEN+size_ip);
    size_tcp = TH_OFF(tcp)*4;
    data = (u_char*)(packet+ETHER_LEN+size_ip+size_tcp);

    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    if(ip_check(swap_word_endian(ethernet->ether_type))
      && tcp_check(ip->ip_p))
    {
      printf("Destination MacAddress\t:");
      printarr(ethernet->ether_dhost,ETHER_ADDR_LEN);
      printf("Source MacAddress\t:");
      printarr(ethernet->ether_shost,ETHER_ADDR_LEN);
      printf("Total length\t\t:%2hu\n",swap_word_endian(ip->ip_len));
      
      hex_to_ip(ip->ip_src,ip_src_str);   // Change hex value to readable ip
      hex_to_ip(ip->ip_dst,ip_dst_str);   // Change hex value to readable ip

      printf("source ip\t\t:%s\n",ip_src_str);
      printf("destination ip\t\t:%s\n",ip_dst_str);
      printf("source port\t\t:%hu\n",swap_word_endian(tcp->th_sport));
      printf("destination port\t:%hu\n",swap_word_endian(tcp->th_dport));
    
      size_data = swap_word_endian(ip->ip_len)-size_ip-size_tcp;
      printf("data length\t\t:%2hu\n",size_data);

      if(size_data > 0)
      {
        printf("Data\t\t\t:");
        printarr(data,size_data > 16 ? 16 : size_data );
      }
      else  printf("No data\n");

      printf("\n");
    }
  }

  pcap_close(handle);
  return 0;
}