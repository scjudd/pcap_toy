#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
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

    printf("Packet #%d:\n", count);

    const struct ether_header *ethernet = (struct ether_header*)(packet);
    char ether_src[ETHER_ADDRSTRLEN];
    char ether_dst[ETHER_ADDRSTRLEN];
    eth_ntoa(ethernet->ether_shost, ether_src, ETHER_ADDRSTRLEN);
    eth_ntoa(ethernet->ether_dhost, ether_dst, ETHER_ADDRSTRLEN);
    printf("\tETH: %s -> %s\n", ether_src, ether_dst);

    // Is this an IP packet?
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) goto finish;

    const struct ip *ip = (struct ip*)(packet + SIZE_ETHERNET);
    size_t size_ip = ip->ip_hl * 4;
    char ip_src[INET_ADDRSTRLEN];
    char ip_dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->ip_src), ip_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->ip_dst), ip_dst, INET_ADDRSTRLEN);
    printf("\tIP:  %s -> %s\n", ip_src, ip_dst);

    // Is this a TCP packet?
    if (ip->ip_p != IPPROTO_TCP) goto finish;

    const struct tcphdr *tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);
    size_t size_tcp = tcp->th_off * 4;
    unsigned short tcp_src = ntohs(tcp->th_sport);
    unsigned short tcp_dst = ntohs(tcp->th_dport);
    printf("\tTCP: %d -> %d\n", tcp_src, tcp_dst);

    // Is this an HTTP packet?
    if (tcp_src != 80 && tcp_dst != 80) goto finish;

    const u_char *payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
    size_t size_payload = ntohs(ip->ip_len) - size_ip - size_tcp;
    if (size_payload > 0) {
        printf("\n%s", payload);
    }

finish:
    printf("\n");
    return;
}

int main(int argc, char *argv[]) {

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <device> [filter]\n", argv[0]);
        exit(1);
    }

    char *device = argv[1];
    char *filter = (argc > 2) ? argv[2] : "";

    if (argc > 2) {
        printf("Starting \"%s\" capture on %s.\n", filter, device);
    } else {
        printf("Starting capture on %s.\n", device);
    }

    // Used to store an error message before a pcap_t is created.
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

#ifdef __APPLE__
    // OS X needs to have a timeout set, or packets may never get delivered.
    // This doesn't seem to be required under Gentoo Linux, and packets get
    // delivered much faster when this isn't set.
    if (pcap_set_timeout(handle, 1000) != 0) {
        pcap_perror(handle, "pcap_set_timeout");
        exit(1);
    }
#endif

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
