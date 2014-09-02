#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <netinet/if_ether.h>

#define ETHER_ADDR_FMT_LEN  18

int format_ether_addr(const u_int8_t *adr, char *dst) {
    return sprintf(dst, "%02x:%02x:%02x:%02x:%02x:%02x",
            adr[0], adr[1], adr[2], adr[3], adr[4], adr[5]);
}

void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    static int count = 0;
    count++;

    const struct ether_header *ethernet;
    ethernet = (struct ether_header*)packet;

    char src_addr[ETHER_ADDR_FMT_LEN]; // Source Ethernet host
    format_ether_addr(ethernet->ether_shost, src_addr);

    char dst_addr[ETHER_ADDR_FMT_LEN]; // Destination Ethernet host
    format_ether_addr(ethernet->ether_dhost, dst_addr);

    printf("Packet #%d:\n", count);
    printf("    Source:      %s\n", src_addr);
    printf("    Destination: %s\n", dst_addr);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];

    bpf_u_int32 net;        // Our IP
    bpf_u_int32 mask;       // Our netmask
    struct bpf_program fp;  // The compiled filter

    const char *filter = "ip and port 80";
    const char *device = argv[1];

    if (argc == 1) {
        fprintf(stderr, "usage: %s <device>\n", argv[0]);
        exit(1);
    }

    // Find properties from capture device
    if (pcap_lookupnet(device, &net, &mask, errbuf) != 0) {
        fprintf(stderr, "pcap_lookupnet error: %s\n", errbuf);
        exit(1);
    }

    // Capture from ethernet device
    pcap_t *handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_create error: %s\n", errbuf);
        exit(1);
    }

    // Activate the capture handle
    if (pcap_activate(handle) != 0) {
        pcap_perror(handle, "pcap_activate");
        exit(1);
    }

    // Compile capture filter
    if (pcap_compile(handle, &fp, filter, 0, net) != 0) {
        pcap_perror(handle, "pcap_compile");
        exit(1);
    }

    // Set capture filter
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "pcap_setfilter");
        exit(1);
    }

    printf("Starting '%s' capture.\n", filter);

    // Enter pcap_loop
    if (pcap_loop(handle, -1, got_packet, NULL) != 0) {
        pcap_perror(handle, "pcap_loop");
        exit(1);
    }

    return 0;
}
