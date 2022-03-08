#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>


#include "errno.h"

#define BUFF_SIZE 65536
#define NAME_SIZE 256
#define PROMISCUOUS 1
#define SIZE_ETHERNET 14
#define SIZE_LOOP_BACK 4

int port_n;
int packet_n = 10;
char interface_name[NAME_SIZE];

bool if_flag = false;
bool tcp_flag = false;
bool udp_flag = false;
bool arp_flag = false;
bool icmp_flag = false;

pcap_t *handle;
int header_size;

void print_interfaces();
void print_help();

// prints error message
// returns param err_n
int handle_error(const int err_n) {
    switch (err_n) {
        case ERR_PORT_N:
            fprintf(stderr, "ERROR: Invalid port specification.\n");
            return ERR_PORT_N;
        case ERR_PACKET_N:
            fprintf(stderr, "ERROR: Invalid packet number specification.\n");
            return ERR_PACKET_N;
        case ERR_ARGUMENT:
            fprintf(stderr, "ERROR: Invalid argument.\n");
            return ERR_ARGUMENT;
        case ERR_INTERFACE:
            print_interfaces();
            fprintf(stderr, "ERROR: Invalid interface name.\n");
            return ERR_INTERFACE;
        case ERR_DATA_RCV:
            fprintf(stderr, "ERROR: Failed to read data from socket.\n");
            return ERR_DATA_RCV;
        case ERR_INTERFACE_DISCOVERY:
            fprintf(stderr, "ERROR: No network interfaces were found. Try with sudo?\n");
            return ERR_INTERFACE_DISCOVERY;
        case ERR_SNIFF_OPEN:
            fprintf(stderr, "ERROR: Failed to open a sniffing session.\n");
            return ERR_SNIFF_OPEN;
        case ERR_DATA_LINK_HEADER:
            fprintf(stderr, "ERROR: Failed to get data link header size.\n");
            return ERR_DATA_LINK_HEADER;
        case ERR_START:
            print_help();
            return ERR_START;
        default:
            fprintf(stderr, "ERROR: Unknown.\n");
            return ERROR;
    }
}

void print_help() {
    // TODO: add something actually helpful
    printf("Printing some info that should help.");
}

// prints all available network interfaces
void print_interfaces() {
    struct if_nameindex *if_ni, *i;
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        printf("No network interfaces were found.\n");
    } else {
        printf("Choose a network interface: \n");
        for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
            printf("%s\n", i->if_name);
        }
        if_freenameindex(if_ni);
    }
}

// verifies integer value
// return 0 on success, -1 otherwise
int verify_int(char *int_str) {
    char *p;
    long return_val = strtol(int_str, &p, 10);
    if (*p != '\0') {
        return -1;
    }
    return (int)return_val;
}

// verifies if supplied network interface is available
// returns true if found @param char *name, false otherwise
bool verify_interface(char *name) {
    struct if_nameindex *if_ni, *i;
    if_ni = if_nameindex();
    bool found = false;
    if (if_ni == NULL) {
        printf("Cannot verify network interface. No network interfaces were found.\n");
    } else {
        for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
            if (!strcmp(i->if_name, name)) {
                printf("[ OK ] Found interface: %s", name);
                found = true;
                // cannot return, need to deallocate first
            }
        }
        if_freenameindex(if_ni);
    }
    return found;
}

// processes and verifies input arguments
// return 0 on success, errno otherwise
int process_arguments(int argc, char *argv[]) {
    // at least interface must be specified
    if (argc < 3) {
        return handle_error(ERR_START);
    }

    // get arguments and set flags
    int arg_pos = 1;
    while (arg_pos != argc) {
        char *arg = argv[arg_pos];
        if (!strcmp(arg, "-p") || !strcmp(arg, "--p")) {
            if (arg_pos < argc - 1) {
                int result = verify_int(argv[arg_pos + 1]);
                if (result < 0) {
                    return handle_error(ERR_PORT_N);
                }
                port_n = result;
                arg_pos += 2;
            } else {
                return handle_error(ERR_PORT_N);
            }
        } else if (!strcmp(arg, "-t") || !strcmp(arg, "--tcp")) {
            tcp_flag = true;
            arg_pos++;
        } else if (!strcmp(arg, "-u") || !strcmp(arg, "--udp")) {
            udp_flag = true;
            arg_pos++;
        } else if (!strcmp(arg, "--arp")) {
            arp_flag = true;
            arg_pos++;
        } else if (!strcmp(arg, "--icmp")) {
            icmp_flag = true;
            arg_pos++;
        } else if (!strcmp(arg, "-i") || !strcmp(arg, "--interface")) {
            if (arg_pos < argc - 1) {
                if (verify_interface(argv[arg_pos + 1])) {
                    strcpy(interface_name, argv[arg_pos + 1]);
                    if_flag = true;
                } else {
                    return handle_error(ERR_INTERFACE);
                }
            } else {
                return handle_error(ERR_INTERFACE);
            }
            arg_pos += 2;
        } else if (!strcmp(arg, "-n")) {
            if (arg_pos < argc - 1) {
                int result = verify_int(argv[arg_pos + 1]);
                if (result < 0) {
                    return handle_error(ERR_PACKET_N);
                }
                packet_n = result;
                arg_pos += 2;
            } else {
                return handle_error(ERR_PACKET_N);
            }
        } else {
            return handle_error(ERR_ARGUMENT);
        }
    }
    return 0;
}

//int process_packet(unsigned char *buffer, ssize_t data_size) {
//}

// TODO: terminating function for signals
//void stop_capture(int signo)
//{
//    struct pcap_stat stats;
//
//    if (pcap_stats(handle, &stats) >= 0) {
//        printf("\n%d packets captured\n", packets);
//        printf("%d packets received by filter\n", stats.ps_recv);
//        printf("%d packets dropped\n\n", stats.ps_drop);
//    }
//    pcap_close(handle);
//    exit(0);
//}

int init_pcap_handle() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface_name, BUFF_SIZE, PROMISCUOUS, 1000, error_buffer);
    if (handle == NULL) {
        return handle_error(ERR_SNIFF_OPEN);
    }
    // TODO: add filtering option
    return 0;
}

int get_dl_header_size() {
    int header_type = pcap_datalink(handle);
    if (header_type == PCAP_ERROR_NOT_ACTIVATED) {
        return handle_error(ERR_DATA_LINK_HEADER);
    }
    switch (header_type) {
        case DLT_NULL:
            return SIZE_LOOP_BACK;
        case DLT_EN10MB:
            return SIZE_ETHERNET;
        default:
            printf("Unsupported data-link type.\n");
            return -1;
    }
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");
}


void print_ether_info(struct ether_header *eth_header, uint16_t *eth_type) {
    struct ether_addr eth_dst, eth_src;

    // find ethernet destination and source address
    memcpy(&eth_dst, eth_header->ether_dhost, sizeof(eth_dst));
    memcpy(&eth_src, eth_header->ether_shost, sizeof(eth_src));

    char *address = ether_ntoa(&eth_dst);
    printf("Ether destination: %s\n", address);
    address = ether_ntoa(&eth_src);
    printf("Ether source: %s\n", address);

    *eth_type = htons(eth_header->ether_type);
}


void
print_payload(const u_char *payload, int len)
{

    int len_rem = len;
    int line_width = 16;			/* number of bytes per line */
    int line_len;
    int offset = 0;					/* zero-based offset counter */
    const u_char *ch = payload;

    if (len <= 0)
        return;

    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    uint16_t eth_type;

    printf("*** NEW PACKET ***\n");

    char *time = ctime(&header->ts.tv_sec);

    printf("At time: %s", time);

    // define ethernet header
    eth_header = (struct ether_header*)(packet);

    // print source, destination and get ether type
    print_ether_info(eth_header, &eth_type);

    switch (eth_type) {
        case ETH_P_IP:
            printf("Ethernet type: IPv4\n");
            break;
        case ETH_P_IPV6:
            printf("Ethernet type: IPv6\n");
            break;
        case ETH_P_ARP:
            printf("Ethernet type: ARP\n");
            break;
        default:
            printf("Ethernet type: unknown\n");
            break;
    }


    printf("*** *** *** *** ***\n\n\n");

    // struct iphdr *ip_header;
    //ip_header = (struct iphdr*)(packet + SIZE_ETHERNET);







//    static int count = 1;                   /* packet counter */
//
//    /* declare pointers to packet headers */
//    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
//    const struct sniff_ip *ip;              /* The IP header */
//    const struct sniff_tcp *tcp;            /* The TCP header */
//    const char *payload;                    /* Packet payload */
//
//    int size_ip;
//    int size_tcp;
//    int size_payload;
//
//    printf("\nPacket number %d:\n", count);
//    count++;
//
//    /* define ethernet header */
//    ethernet = (struct sniff_ethernet*)(packet);
//
//    /* define/compute ip header offset */
//    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
//    size_ip = IP_HL(ip)*4;
//    if (size_ip < 20) {
//        printf("   * Invalid IP header length: %u bytes\n", size_ip);
//        return;
//    }



}


int main(int argc, char *argv[]) {
    *interface_name = 0;
    int result = process_arguments(argc, argv);
    if (result != 0) {
        return result;
    }

    // TODO: change the behaviour of signals
    // signal()

    printf("Starting...\n");

    result = init_pcap_handle();
    if (result != 0) {
        return result;
    }

    header_size = get_dl_header_size();
    if (header_size == -1) {
        // TODO: unsupported data link type?
        return -1;
    }

    pcap_loop(handle, packet_n, got_packet, NULL);

    return 0;
}
