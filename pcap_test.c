#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>

#define ETHER_ADDR_FMT_LEN  18

void format_ether_addr(const u_int8_t *adr, char *dst) {
    sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
            adr[0], adr[1], adr[2], adr[3], adr[4], adr[5]);
}

void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    static int count = 0;
    count++;

    const struct ether_header *ethernet;
    ethernet = (struct ether_header*)packet;

    char src_addr[ETHER_ADDR_FMT_LEN];
    format_ether_addr(ethernet->ether_shost, src_addr);

    char dst_addr[ETHER_ADDR_FMT_LEN];
    format_ether_addr(ethernet->ether_dhost, dst_addr);

    printf("Packet #%d:\n", count);
    printf("    Source:      %s\n", src_addr);
    printf("    Destination: %s\n", dst_addr);
}

int main(int argc, char *argv[]) {

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s <device> [filter]\n", argv[0]);
        exit(1);
    }

    const char *device = argv[1];
    const char *filter = (argc > 2) ? argv[2] : "";

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

    if (argc > 2) {
        printf("Starting \"%s\" capture on %s.\n", filter, device);
    } else {
        printf("Starting capture on %s.\n", device);
    }

    if (pcap_loop(handle, -1, got_packet, NULL) != 0) {
        pcap_perror(handle, "pcap_loop");
        exit(1);
    }
}
