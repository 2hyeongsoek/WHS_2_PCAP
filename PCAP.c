#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "myheader.h"

void packet_capture(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

    struct ethheader *eth = (struct ethheader *)packet;
    struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
    struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip->iph_ihl*4);
    
    printf("========Ethernet Header:======\n");
    printf("Src MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_shost));
    printf("Dst MAC: %s\n", ether_ntoa((struct ether_addr *)eth->ether_dhost));

    printf("===========IP Header==========\n");
    printf("Src IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("Dst IP: %s\n", inet_ntoa(ip->iph_destip));

    printf("==========TCP Header==========\n");
    printf("Src Port: %d\n", ntohs(tcp->tcp_sport));
    printf("Dst Port: %d\n", ntohs(tcp->tcp_dport));

    printf("=========Packet Data==========\n");
    for (int i = 0; i < header->caplen; i++) {
        printf("%02x ", packet[i]);
    }
    printf("\n\n");

    printf("\n");
}

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_live("eth0", BUFSIZ, 1, 6000, errbuf);

    pcap_loop(handle, 0, packet_capture, NULL);
    pcap_close(handle);

    return 0;
}