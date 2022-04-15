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
#include "dynamic_string.h"

// Sufficient for IPv4 and IPv6(except for Jumbogram header option) packets.
// Total Length field is a 16-bit unsigned integer, which has a possible 65,536 values.
#define LONG_BUFF_SIZE 65536
#define SMALL_BUFF_SIZE 256
#define PROMISCUOUS 1
#define INF_LOOP 0
#define SIZE_ETH_H 14
#define SIZE_LOOP_BACK_H 4

char string_buffer[LONG_BUFF_SIZE] = {0};

bool tcp_flag   = false;
bool udp_flag   = false;
bool arp_flag   = false;
bool icmp_flag  = false;

int return_code = 0;

int port_n;
bool port_n_is_set = false;
int packet_n = 1;
char interface_name[SMALL_BUFF_SIZE];

pcap_t *handle;
int header_size;

typedef struct packet_t{
    unsigned long   frame_length;
    unsigned long   payload_size;
    unsigned long   dl_header_size;
    string_t        protocol;
    string_t        time_stamp;
    string_t        eth_type;
    string_t        mac_src;
    string_t        mac_dst;
    string_t        ip_src;
    string_t        ip_dst;
    string_t        port_src;
    string_t        port_dst;
    string_t        frame_content;
} packet_t;

struct packet_t packet_storage;

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
        case ERR_IP_HEADER_SIZE:
            fprintf(stderr, "ERROR: Invalid IP frame header size(<5).\n");
            return ERR_IP_HEADER_SIZE;
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
        for (i = if_ni; !(i->if_index == 0 && i->if_name == NULL); i++) {
            printf("%s\n", i->if_name);
        }
        // free space allocated for names of interfaces
        if_freenameindex(if_ni);
    }
}

void reinit_packet_storage_struct() {
    str_free(&packet_storage.time_stamp);
    str_free(&packet_storage.protocol);
    str_free(&packet_storage.mac_src);
    str_free(&packet_storage.mac_dst);
    str_free(&packet_storage.ip_src);
    str_free(&packet_storage.ip_dst);
    str_free(&packet_storage.port_src);
    str_free(&packet_storage.port_dst);
    packet_storage.frame_length = 0;
}

void init_packet_storage_struct() {
    str_create_empty(&packet_storage.time_stamp);
    str_create_empty(&packet_storage.protocol);
    str_create_empty(&packet_storage.mac_src);
    str_create_empty(&packet_storage.mac_dst);
    str_create_empty(&packet_storage.ip_src);
    str_create_empty(&packet_storage.ip_dst);
    str_create_empty(&packet_storage.port_src);
    str_create_empty(&packet_storage.port_dst);
    str_create_empty(&packet_storage.eth_type);
    str_create_empty(&packet_storage.frame_content);
    packet_storage.frame_length = 0;
    packet_storage.payload_size = 0;
    packet_storage.dl_header_size = 0;
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
                port_n_is_set = true;
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
            // unknown argument
            return handle_error(ERR_ARGUMENT);
        }
    }

    // if no specifying flag was set, print all packets
    if (!tcp_flag && !udp_flag && !arp_flag && !icmp_flag) {
        tcp_flag = true;
        udp_flag = true;
        arp_flag = true;
        icmp_flag = true;
    }

    return 0;
}

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

// obtains a packet capture handle to look at packet on the network
int init_pcap_handle() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(interface_name, LONG_BUFF_SIZE, PROMISCUOUS, 1000, error_buffer);
    if (handle == NULL) {
        return handle_error(ERR_SNIFF_OPEN);
    }
    return 0;
}

// assigns link-layer header size according to the handle
int get_dl_header_size() {
    int header_type = pcap_datalink(handle);
    if (header_type == PCAP_ERROR_NOT_ACTIVATED) {
        return handle_error(ERR_DATA_LINK_HEADER);
    }
    switch (header_type) {
        case DLT_NULL:
            packet_storage.frame_length += SIZE_LOOP_BACK_H;
            packet_storage.dl_header_size = SIZE_LOOP_BACK_H;
            return SIZE_LOOP_BACK_H;
        case DLT_EN10MB:
            packet_storage.dl_header_size = SIZE_ETH_H;
            packet_storage.frame_length += SIZE_ETH_H;
            return SIZE_ETH_H;
        default:
            printf("Unsupported data-link type.\n");
            return -1;
    }
}

void print_hex_part(const u_char *payload, unsigned long len, unsigned long offset)
{
    // offset:  16 bytes next to each other; same 16 bytes but only printable
    // 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
    const unsigned char *char_ptr;
    sprintf(string_buffer, "0x%04x\t ", offset);
    str_append_string(&packet_storage.frame_content, string_buffer);

    for (unsigned long i = 0; i < len; i++) {
        // +5 to skip Version and Length fields
        char_ptr = (payload + offset + i);
        sprintf(string_buffer, "%02x ", *char_ptr);
        str_append_string(&packet_storage.frame_content, string_buffer);
        if (i == 7) str_append_string(&packet_storage.frame_content, "  ");
    }

    // fill gap if line is not complete
    if (len < 16) {
        for (unsigned long i = 0; i < (unsigned long)16 - len; i++) {
            str_append_string(&packet_storage.frame_content, "   ");
        }
    }
    // tab space between hex and human-readable part
    str_append_string(&packet_storage.frame_content, "\t");

    for (unsigned long i = 0; i < len; i++) {
        // +5 to skip Version and Length fields
        char_ptr = (payload + offset + i);
        if (isprint(*char_ptr)) {
            sprintf(string_buffer, "%c", *char_ptr);
            str_append_string(&packet_storage.frame_content, string_buffer);
        } else {
            str_append_string(&packet_storage.frame_content, ".");
        }
        if (i == 7) str_append_string(&packet_storage.frame_content, "  ");
    }
    str_append_string(&packet_storage.frame_content, "\n");
}

void print_ether_info(struct ether_header *eth_header, uint16_t *eth_type) {
    struct ether_addr eth_dst, eth_src;

    // find ethernet destination and source mac addresses
    memcpy(&eth_src, eth_header->ether_shost, sizeof(eth_src));
    memcpy(&eth_dst, eth_header->ether_dhost, sizeof(eth_dst));

    str_append_string(&packet_storage.mac_src, ether_ntoa(&eth_src));
    str_append_string(&packet_storage.mac_dst, ether_ntoa(&eth_dst));

    *eth_type = htons(eth_header->ether_type);
}

string_t get_frame_content(const u_char *frame) {
    unsigned long bytes_per_line = 16;
    unsigned long offset;

    unsigned long number_of_full_lines;
    unsigned long total_number_of_lines;
    unsigned long remainder;

    number_of_full_lines = packet_storage.frame_length / bytes_per_line;
    total_number_of_lines = number_of_full_lines;
    remainder = packet_storage.frame_length % bytes_per_line;

    if (remainder) total_number_of_lines++;

    for (unsigned long  line = 0; line < total_number_of_lines; line++) {
        offset = line * bytes_per_line;
        if (line == number_of_full_lines && remainder) {
            print_hex_part(frame, remainder, offset);
        } else {
            print_hex_part(frame, bytes_per_line, offset);
        }
    }
}

void print_ipv4_tcp_packet(const u_char *packet, const uint16_t ip_total_length, const unsigned int ip_header_length) {
    struct tcphdr *tcp_header;
    uint8_t tcp_header_length;

    tcp_header = (struct tcphdr*)(packet + SIZE_ETH_H + ip_header_length);

    sprintf(string_buffer, "%hu", ntohs(tcp_header->th_sport));
    str_append_string(&packet_storage.port_src, string_buffer);
    sprintf(string_buffer, "%hu", ntohs(tcp_header->th_dport));
    str_append_string(&packet_storage.port_dst, string_buffer);

    tcp_header_length = tcp_header->th_off;
    tcp_header_length *= 4;

    uint16_t payload_size = ip_total_length - (ip_header_length + tcp_header_length);
    packet_storage.payload_size = payload_size;
    get_frame_content(packet);

}

void print_ipv4_udp_packet(const u_char *packet, const unsigned int ip_header_length) {
    struct udphdr *udp_header;
    const uint8_t tcp_header_length = 8;

    udp_header = (struct udphdr*)(packet + SIZE_ETH_H + ip_header_length);

    sprintf(string_buffer, "%hu\n", ntohs(udp_header->uh_sport));
    str_append_string(&packet_storage.port_src, string_buffer);

    sprintf(string_buffer, "%hu\n", ntohs(udp_header->uh_dport));
    str_append_string(&packet_storage.port_dst, string_buffer);

    uint16_t size_payload = ntohs(udp_header->uh_ulen) - tcp_header_length;
    packet_storage.payload_size = size_payload;
}

void print_ipv4_icmp_packet(const u_char *packet, const uint16_t ip_total_length, const unsigned int ip_header_length) {
//    struct icmphdr *icmp_header;
//    const u_char *payload;
//    const uint8_t icmp_header_length = 8;
//
//    printf("IP header length: %d\n", ip_header_length);
//    printf("IP total length: %d\n", ip_total_length);
//
//    udp_header = (struct udphdr*)(packet + SIZE_ETH_H + ip_header_length);
//
//    printf("Source port: %hu\n", ntohs(udp_header->uh_sport));
//    printf("Destination port: %hu\n", ntohs(udp_header->uh_dport));
//
//    uint16_t size_payload = ntohs(udp_header->uh_ulen) - tcp_header_length;
//    payload = (u_char *)(packet + SIZE_ETH_H + ip_header_length + tcp_header_length);
//    printf("Payload size: %d\n", size_payload);
//
//    get_frame_content(payload, size_payload);

    printf("ipv4 icmp\n");
}

void print_ipv4_arp_packet(const u_char *packet, const uint16_t ip_total_length, const unsigned int ip_header_length) {
//    struct arphdr *arp_header;
//    const u_char *payload;
//    uint8_t tcp_header_length;
//
//    printf("IP header length: %d\n", ip_header_length);
//    printf("IP total length: %d\n", ip_total_length);
//
//
//    arp_header = (struct arphdr*)(packet + SIZE_ETH_H + ip_header_length);
//
//    printf("Source port: %hu\n", ntohs(arp_header->));
//    printf("Destination port: %hu\n", ntohs(arp_header));
//
//    tcp_header_length = tcp_header->th_off;
//    tcp_header_length *= 4;
//    printf("TCP header length: %d\n", tcp_header_length);
//
//    uint16_t size_payload = ip_total_length - (ip_header_length + tcp_header_length);
//    payload = (u_char *)(packet + SIZE_ETH_H + ip_header_length + tcp_header_length);
//    printf("Payload size: %d\n", size_payload);
//
//    get_frame_content(payload, size_payload);

    printf("ipv4 arp\n");
}

int print_ipv4_packet(const u_char *packet) {
    struct iphdr *ip_header;
    uint8_t ip_protocol;
    unsigned int ip_header_length;
    uint16_t ip_total_length;

    ip_header = (struct iphdr*)(packet + packet_storage.dl_header_size);
    ip_protocol = ip_header->protocol;

    // multiplying by 4, ihl is 4 bit field indicating the number of 4 byte blocks
    ip_header_length = ip_header->ihl;
    if (ip_header_length < 5) {
        // should be at least 5
        // https://learningnetwork.cisco.com/s/question/0D53i00000Kt7fqCAB/what-is-ihl-filed-in-ipv4
        return ERR_IP_HEADER_SIZE;
    }
    ip_header_length *= 4;
    ip_total_length = ntohs(ip_header->tot_len);

    // now the length value is final for current packet
    packet_storage.frame_length += ip_total_length;
    printf("Source ip: %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    str_append_string(&packet_storage.ip_src, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    str_append_string(&packet_storage.ip_dst, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

    switch (ip_protocol) {
        case IPPROTO_TCP:
            str_append_string(&packet_storage.protocol, "TCP");
            print_ipv4_tcp_packet(packet, ip_total_length, ip_header_length);
            break;
        case IPPROTO_UDP:
            str_append_string(&packet_storage.protocol, "UDP");
            print_ipv4_udp_packet(packet, ip_header_length);
            break;
        case IPPROTO_ICMP:
            str_append_string(&packet_storage.protocol, "ICMP");
            //print_ipv4_icmp_packet(packet, ip_total_length, ip_header_length);
            break;
        default:
            str_append_string(&packet_storage.protocol, "unknown");
            break;
    }
    return 0;
}

void print_ipv6_packet(const u_char *packet) {
    struct iphdr *ip_header;
    uint8_t protocol;

    ip_header = (struct iphdr*)(packet + packet_storage.dl_header_size);
    // TODO: check header length

    protocol = ip_header->protocol;

    switch (protocol) {
        case IPPROTO_TCP:
            printf("IPv6 protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("IPv6 protocol: UDP\n");
            break;
        case IPPROTO_ICMPV6:
            printf("IPv6 protocol: ICMPv6\n");
            break;
        default:
            printf("IPv6 protocol: unknown\n");
            break;
    }
}

void get_time_from_pkthdr(const struct pcap_pkthdr *header) {
    char time_string[40];
    struct tm* broken_down_time = localtime(&header->ts.tv_sec);
    strftime(time_string, sizeof (time_string), "%Y-%m-%d %H:%M:%S", broken_down_time);
    long milliseconds = header->ts.tv_usec / 1000;
    sprintf(string_buffer, "%s.%03ld", time_string, milliseconds);
    str_append_string(&packet_storage.time_stamp, string_buffer);
}

void print_packet() {
    printf("*** NEW PACKET ***\n");
    printf("src MAC:        %s\n", packet_storage.mac_src.ptr);
    printf("dst MAC:        %s\n", packet_storage.mac_dst.ptr);
    printf("frame length:   %lu\n", packet_storage.frame_length);
    printf("src IP:         %s\n", packet_storage.ip_src.ptr);
    printf("dst IP:         %s\n", packet_storage.ip_dst.ptr);
    printf("src port:       %s\n", packet_storage.port_src.ptr);
    printf("dst port:       %s\n", packet_storage.port_dst.ptr);
    printf("payload size:   %lu\n", packet_storage.payload_size);
    printf("frame: \n%s", packet_storage.frame_content.ptr);


    // TODO: print entire packet frame
    printf("*** END OF PACKET ***\n\n\n");
}

void check_and_print_packet() {
    bool passed = false;
    // filter packets that are not supposed to be written out
    string_t *protocol = &packet_storage.protocol;
    if (!strcmp(protocol->ptr, "TCP") && tcp_flag) passed = true;
    if (!strcmp(protocol->ptr, "UDP") && udp_flag) passed = true;
    if (!strcmp(protocol->ptr, "ARP") && arp_flag) passed = true;
    if (!strcmp(protocol->ptr, "ICMP") && icmp_flag) passed = true;

    // packet did not pass
    if (!passed) {
        return;
    }

    packet_n--;
    print_packet();
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    uint16_t eth_type;

    get_time_from_pkthdr(header);

    // define ethernet header
    eth_header = (struct ether_header*)(packet);

    // print source, destination and get ether type
    print_ether_info(eth_header, &eth_type);

    switch (eth_type) {
        case ETH_P_IP:
            str_append_string(&packet_storage.eth_type, "IPv4");
            return_code = print_ipv4_packet(packet);
            break;
        case ETH_P_IPV6:
            str_append_string(&packet_storage.eth_type, "IPv6");
            break;
        case ETH_P_ARP:
            str_append_string(&packet_storage.eth_type, "ARP");
            break;
        default:
            str_append_string(&packet_storage.eth_type, "unknown");
            break;
    }

    // break if we found given number of packets we were looking for
    if (packet_n == 0) {
        pcap_breakloop(handle);
        return;
    }

    check_and_print_packet();
}

int main(int argc, char *argv[]) {
    init_packet_storage_struct();
    *interface_name = 0;
    int result = process_arguments(argc, argv);
    if (result != 0) {
        return result;
    }

    // TODO: do I need this?
    // init_packet_storage_struct();

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

    // when terminated by pcap_breakloop(), returns PCAP_ERROR_BREAK(-2)
    pcap_loop(handle, INF_LOOP, got_packet, NULL);

    return 0;
}
