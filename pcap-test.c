#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include<netinet/in.h>
#include<stdint.h>
#include<stddef.h> /// ?????????? 이거 뭐지
#define ETHER_ADDR_LEN 6
#define LIBNET_LIL_ENDIAN true

/*
struct pcap_pkthdr{
	struct timecal ts; // 캡쳐된 시간정보 저장
	pbf_u_int32 caplen; // 캡쳐한 패킷 길이 저장
	bpf_u_int32 len; // 패킷의 길이가 저장
};
*/

// include/libnet/libnet-headers, 479 line
/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
};

// 647 line
/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    u_int8_t ip_src[4];
    u_int8_t ip_dst[4];
    //struct in_addr ip_src, ip_dst; /* source and dest address */
};

// 1519 line
/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
};

void Packet_parsing(const u_char* packet, u_int32_t len){
	// packet_parsing - eth + ip + tcp + data
	// if get TCP packet - print 1-4 data (print if data size >=0)
	// 1. eth header src mac/dst mac
	// 2. ip header src ip/ dst ip
	// 3. tcp header src port/ dst port
	// 4. payload's hexadeciaml value (max 20byte)
	struct libnet_ethernet_hdr *ethernet;
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
        u_char *payload;
        int data_idx;

	ethernet = (struct libnet_ethernet_hdr *) packet;
	ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ip->ip_hl*4));
        payload = (u_char *)(packet + sizeof(struct libnet_ethernet_hdr) + (ip->ip_hl*4) + (tcp->th_off * 4));
        data_idx = len - (sizeof(struct libnet_ethernet_hdr) + (ip->ip_hl*4) + (tcp -> th_off * 4));
        if(data_idx > 20) data_idx=20;

        if(ip->ip_p!=6){
          return;
        }
	
	printf("----------------\n");
	printf("1. eth header\n");
        printf("src mac : ");
        for(int i=0;i<6;i++){
          printf("%02X",ethernet->ether_shost[i]);
          if(i!=6-1){
            printf("-");
          }
        }
        printf("\n");

        printf("dst mac : ");
        for(int i=0;i<6;i++){
          printf("%02X",ethernet->ether_dhost[i]);
          if(i!=6-1){
            printf("-");
          }
        }
        printf("\n");

        printf("2. ip header\n");
        printf("src ip : ");
        for(int i=0;i<4;i++){
          printf("%d",ip->ip_src[i]);
          if(i!=4-1){
            printf(".");
          }
        }
        printf("\n");

        printf("dst ip : ");
        for(int i=0;i<4;i++){
          printf("%d",ip->ip_dst[i]);
          if(i!=4-1){
            printf(".");
          }
        }
        printf("\n");

	printf("3. tcp header\n");
        printf("src port : %d\n",ntohs(tcp->th_sport));
        printf("dst port : %d\n",ntohs(tcp->th_dport));

	printf("4. payload's hexadeciaml value (max 20byte)\n");
        for(int i=0;i<data_idx;i++){
          printf("%02X ",payload[i]);
          }
        printf("\n");
        }



void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		//printf("%u bytes captured\n", header->caplen);
                Packet_parsing(packet,header->caplen);
	}
	pcap_close(pcap);
}

