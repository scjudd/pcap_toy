#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define ETHER_ADDRSTRLEN    18
#define SIZE_ETHERNET       14

void eth_ntoa(const u_char *src, char *dst, size_t size) {
    snprintf(dst, size, "%02x:%02x:%02x:%02x:%02x:%02x",
        src[0], src[1], src[2], src[3], src[4], src[5]);
}

void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    static int count = 0;
    count++;

    const struct ether_header *ethernet;
    const struct ip *ip;

    ethernet = (struct ether_header*)(packet);
    char ether_src[ETHER_ADDRSTRLEN];
    char ether_dst[ETHER_ADDRSTRLEN];
    eth_ntoa(ethernet->ether_shost, ether_src, ETHER_ADDRSTRLEN);
    eth_ntoa(ethernet->ether_dhost, ether_dst, ETHER_ADDRSTRLEN);

    ip = (struct ip*)(packet + SIZE_ETHERNET);
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);

    printf("Packet #%d:\n", count);
    printf("\tETH: %s -> %s\n", ether_src, ether_dst);
    printf("\tIP:  %s -> %s\n", ip_src, ip_dst);
}

int main(int argc, char *argv[]) {

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <device> [filter]\n", argv[0]);
        exit(1);
    }

    char *device = argv[1];
    char *filter;
    if (argc > 2) {
        filter = argv[2];
        printf("Starting \"%s\" capture on %s.\n", filter, device);
    } else {
        filter = "";
        printf("Starting capture on %s.\n", device);
    }

    // used to store an error message before a pcap_t is created
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 ip;
    bpf_u_int32 netmask;
    if (pcap_lookupnet(device, &ip, &netmask, errbuf) != 0) {
        fprintf(stderr, "pcap_lookupnet: %s\n", errbuf);
        exit(1);
    }

    pcap_t *handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create: %s\n", errbuf);
        exit(1);
    }

    if (pcap_set_timeout(handle, 1000) != 0) {
        pcap_perror(handle, "pcap_set_timeout");
        exit(1);
    }

    if (pcap_activate(handle) != 0) {
        pcap_perror(handle, "pcap_activate");
        exit(1);
    }

    struct bpf_program fp;  // the compiled filter
    if (pcap_compile(handle, &fp, filter, 0, ip) != 0) {
        pcap_perror(handle, "pcap_compile");
        exit(1);
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "pcap_setfilter");
        exit(1);
    }

    if (pcap_loop(handle, -1, got_packet, NULL) != 0) {
        pcap_perror(handle, "pcap_loop");
        exit(1);
    }
}
