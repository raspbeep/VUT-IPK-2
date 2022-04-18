/**
 * ipk-sniffer
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file ipk-sniffer.c
 *
 * @brief Packet capture and analysis tool
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <net/if.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>

#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>

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
#define IPV6_HEADER_SIZE 40

// temporary storage until string is written into packet_storage
char string_buffer[LONG_BUFF_SIZE] = {0};

// filter flags
bool tcp_flag   = false;
bool udp_flag   = false;
bool arp_flag   = false;
bool icmp_flag  = false;
bool ipv4_flag  = false;
bool ipv6_flag  = false;

char *port_n;
bool port_n_is_set = false;
int packet_n = 1;
char interface_name[SMALL_BUFF_SIZE];

pcap_t *handle;
int header_size;

struct packet_t {
    unsigned long   frame_length;
    unsigned long   payload_size;
    unsigned long   dl_header_size;
    string_t        protocol;
    string_t        time_stamp;
    string_t        eth_type;
    string_t        mac_src;
    string_t        mac_dst;
    string_t        mac6_src;
    string_t        mac6_dst;
    string_t        ip_src;
    string_t        ip_dst;
    string_t        port_src;
    string_t        port_dst;
    string_t        frame_content;
    string_t        icmp_type;
    string_t        arp_hw_type;
    string_t        arp_protocol_type;
    string_t        arp_operation;
};

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
    printf( "ipk-sniffer A network analyzer tool\n"
                    "Usage: ./ipk-sniffer [-i|--interface]{-p port}{[--tcp|-t][--udp|-u][--arp][--icmp]}{-n}\n"
                    "   -i|--interface - specify name of network interface to use\n"
                    "   -p             - filter by port (either src and dst matching wil be printed out)\n"
                    "   --tcp|-t       - filter by TCP protocol\n"
                    "   --udp|-u       - filter by UDP protocol\n"
                    "   --arp          - filter by ARP protocol\n"
                    "   --icmp         - filter by ICMP protocol (both IPv4 and IPv6)\n"
                    "   --ipv4/--ipv6  - filter by IP version number\n"
                    "   -n             - number of packets to print\n\n"
                    );
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

// creates empty string_t fields in global package_storage struct
void init_packet_storage_struct() {
    str_create_empty(&packet_storage.time_stamp);
    str_create_empty(&packet_storage.protocol);
    str_create_empty(&packet_storage.mac_src);
    str_create_empty(&packet_storage.mac_dst);
    str_create_empty(&packet_storage.mac6_src);
    str_create_empty(&packet_storage.mac6_dst);
    str_create_empty(&packet_storage.ip_src);
    str_create_empty(&packet_storage.ip_dst);
    str_create_empty(&packet_storage.port_src);
    str_create_empty(&packet_storage.port_dst);
    str_create_empty(&packet_storage.eth_type);
    str_create_empty(&packet_storage.frame_content);
    str_create_empty(&packet_storage.icmp_type);
    str_create_empty(&packet_storage.arp_hw_type);
    str_create_empty(&packet_storage.arp_protocol_type);
    str_create_empty(&packet_storage.arp_operation);
    packet_storage.frame_length = packet_storage.dl_header_size;
    packet_storage.payload_size = 0;
}

// frees string_t fields in package_storage struct variable and creates empty ones
void reinit_packet_storage_struct() {
    str_free(&packet_storage.time_stamp);
    str_free(&packet_storage.protocol);
    str_free(&packet_storage.mac_src);
    str_free(&packet_storage.mac_dst);
    str_free(&packet_storage.mac6_src);
    str_free(&packet_storage.mac6_dst);
    str_free(&packet_storage.ip_src);
    str_free(&packet_storage.ip_dst);
    str_free(&packet_storage.port_src);
    str_free(&packet_storage.port_dst);
    str_free(&packet_storage.eth_type);
    str_free(&packet_storage.frame_content);
    str_free(&packet_storage.icmp_type);
    str_free(&packet_storage.arp_hw_type);
    str_free(&packet_storage.arp_protocol_type);
    str_free(&packet_storage.arp_operation);
    init_packet_storage_struct();
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

// verifies whether network interface given on input is valid and available
bool verify_interface(char *name) {
    struct if_nameindex *if_ni, *i;
    if_ni = if_nameindex();
    bool found = false;
    if (if_ni == NULL) {
        printf("Cannot verify network interface. No network interfaces were found.\n");
        return false;
    } else {
        for (i = if_ni; ! (i->if_index == 0 && i->if_name == NULL); i++) {
            if (!strcmp(i->if_name, name)) {
                printf("[ OK ] Found interface: %s\n", name);
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
        print_interfaces();
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
                port_n = argv[arg_pos + 1];
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
        } else if (!strcmp(arg, "--ipv4")) {
            ipv4_flag = true;
            arg_pos++;
        } else if (!strcmp(arg, "--ipv6")) {
            ipv6_flag = true;
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

// sets default handler for terminating the process
void stop_capture(int signal_number) {
    pcap_close(handle);

    printf("\nExiting...(%d)\n", signal_number);
    exit(0);
}

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

// transforms frame content into a human-readable format
void frame_content_printer(const u_char *payload, unsigned long len, unsigned long offset)
{
    // offset:  16 bytes next to each other; same 16 bytes but only printable
    // 0x0000:  00 19 d1 f7 be e5 00 04  96 1d 34 20 08 00 45 00  ........ ..4 ..
    const unsigned char *char_ptr;
    sprintf(string_buffer, "0x%04lx\t ", offset);
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

// assigns mac address of ethernet frame to packet storage
void ether_info(struct ether_header *eth_header, uint16_t *eth_type) {
    struct ether_addr eth_dst, eth_src;

    // find ethernet destination and source mac addresses
    memcpy(&eth_src, eth_header->ether_shost, sizeof(eth_src));
    memcpy(&eth_dst, eth_header->ether_dhost, sizeof(eth_dst));

    str_append_string(&packet_storage.mac_src, ether_ntoa(&eth_src));
    str_append_string(&packet_storage.mac_dst, ether_ntoa(&eth_dst));

    *eth_type = htons(eth_header->ether_type);
}

// assigns frame content in human-readable format to packet storage
void get_frame_content(const u_char *frame) {
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
            frame_content_printer(frame, remainder, offset);
        } else {
            frame_content_printer(frame, bytes_per_line, offset);
        }
    }
}

// gets information from IPv4 TCP packet
void ipv4_tcp_packet(const u_char *packet, const uint16_t ip_total_length, const unsigned int ip_header_length) {
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

// gets information from IPv4 UDP packet
void ipv4_udp_packet(const u_char *packet, const unsigned int ip_header_length) {
    struct udphdr *udp_header;
    const uint8_t tcp_header_length = 8;

    udp_header = (struct udphdr*)(packet + SIZE_ETH_H + ip_header_length);

    sprintf(string_buffer, "%hu", ntohs(udp_header->uh_sport));
    str_append_string(&packet_storage.port_src, string_buffer);
    sprintf(string_buffer, "%hu", ntohs(udp_header->uh_dport));
    str_append_string(&packet_storage.port_dst, string_buffer);

    uint16_t payload_size = ntohs(udp_header->uh_ulen) - tcp_header_length;
    packet_storage.payload_size = payload_size;
    get_frame_content(packet);
}

// gets information from IPv4 ICMP packet
void ipv4_icmp_packet(const u_char *packet, const unsigned int ip_header_length) {
    struct icmphdr *icmp_header;

    icmp_header = (struct icmphdr*)(packet + SIZE_ETH_H + ip_header_length);

    switch(icmp_header->type) {
        case ICMP_ECHOREPLY:
            sprintf(string_buffer, "(0) Echo reply.");
            break;
        case ICMP_DEST_UNREACH:
            sprintf(string_buffer, "(3) Destination unreached.");
            break;
        case ICMP_SOURCE_QUENCH:
            sprintf(string_buffer, "(4) Source quench(congestion control).");
            break;
        case ICMP_REDIRECT:
            sprintf(string_buffer, "(5) Redirect.");
            break;
        case ICMP_ECHO:
            sprintf(string_buffer, "(8) Echo.");
            break;
        case ICMP_TIME_EXCEEDED:
            sprintf(string_buffer, "(11) Time exceeded.");
            break;
        case ICMP_PARAMETERPROB:
            sprintf(string_buffer, "(12) Parameter problem.");
            break;
        case ICMP_TIMESTAMP:
            sprintf(string_buffer, "(13) Timestamp.");
            break;
        case ICMP_TIMESTAMPREPLY:
            sprintf(string_buffer, "(14) Timestamp reply.");
            break;
        case ICMP_INFO_REQUEST:
            sprintf(string_buffer, "(15) Info request.");
            break;
        case ICMP_INFO_REPLY:
            sprintf(string_buffer, "(16) Info reply.");
            break;
        default:
            sprintf(string_buffer, "(?) Unknown ICMP type.");
            break;
    }
    str_append_string(&packet_storage.icmp_type, string_buffer);
    get_frame_content(packet);
}

// gets information from ARP packet
int arp_packet(const u_char *packet) {
    struct arphdr *arp_header;

    arp_header = (struct arphdr*)(packet + SIZE_ETH_H);
    unsigned short int hardware_address_format = ntohs(arp_header->ar_hrd);
    unsigned short int protocol_address_format = ntohs(arp_header->ar_pro);
    unsigned short hardware_address_length = arp_header->ar_hln;
    unsigned short protocol_address_length = arp_header->ar_pln;
    unsigned short int arp_operation = ntohs(arp_header->ar_op);

    const int arp_header_length = 8;
    packet_storage.frame_length += arp_header_length;
    packet_storage.frame_length += 2 * hardware_address_length;
    packet_storage.frame_length += 2 * protocol_address_length;

    if (arp_operation == 1) {
        str_append_string(&packet_storage.arp_operation, "request(1)");
    } else if (arp_operation == 2) {
        str_append_string(&packet_storage.arp_operation, "reply(2)");
    }

    str_append_string(&packet_storage.ip_src,
                            inet_ntoa(*(struct in_addr *)(packet + packet_storage.dl_header_size +
                               arp_header_length + hardware_address_length)));
    str_append_string(&packet_storage.ip_dst,
                            inet_ntoa(*(struct in_addr *)(packet + packet_storage.dl_header_size +
                               arp_header_length + hardware_address_length * 2 + protocol_address_length)));

    // Ethernet (1)
    if (hardware_address_format == 1) {
        str_append_string(&packet_storage.arp_hw_type, "Ethernet(1)");
        if (protocol_address_format == 2048) {
            str_append_string(&packet_storage.arp_protocol_type, "IPv4");
            get_frame_content(packet);
        }
    }
    return 0;
}

// base function during IPv4 packet capture
// based on packet protocol decides how to unfold the packet
int ipv4_packet(const u_char *packet) {
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

    str_append_string(&packet_storage.ip_src, inet_ntoa(*(struct in_addr *)&ip_header->saddr));
    str_append_string(&packet_storage.ip_dst, inet_ntoa(*(struct in_addr *)&ip_header->daddr));

    switch (ip_protocol) {
        case IPPROTO_TCP:
            str_append_string(&packet_storage.protocol, "TCP");
            ipv4_tcp_packet(packet, ip_total_length, ip_header_length);
            break;
        case IPPROTO_UDP:
            str_append_string(&packet_storage.protocol, "UDP");
            ipv4_udp_packet(packet, ip_header_length);
            break;
        case IPPROTO_ICMP:
            str_append_string(&packet_storage.protocol, "ICMP");
            ipv4_icmp_packet(packet, ip_header_length);
            break;
        default:
            str_append_string(&packet_storage.protocol, "Unknown IPv4 protocol");
            break;
    }
    return 0;
}

// gets information from IPv6 ICMP packet
void ipv6_icmp_packet(const u_char *packet) {
    struct icmp6_hdr *icmp_header;

    icmp_header = (struct icmp6_hdr*)(packet + SIZE_ETH_H + IPV6_HEADER_SIZE + packet_storage.payload_size);

    switch(icmp_header->icmp6_type) {
        case ICMP6_ECHO_REPLY:
            sprintf(string_buffer, "(129) Echo reply.");
            break;
        case ICMP6_DST_UNREACH:
            sprintf(string_buffer, "(1) Destination unreachable.");
            break;
        case ICMP6_PACKET_TOO_BIG:
            sprintf(string_buffer, "(2) Packet too big.");
            break;
        case ICMP6_TIME_EXCEEDED:
            sprintf(string_buffer, "(3) Time exceeded.");
            break;
        case ICMP6_PARAM_PROB:
            sprintf(string_buffer, "(4) Parameter problem.");
            break;
        case MLD_LISTENER_QUERY:
        case MLD_LISTENER_REPORT:
        case MLD_LISTENER_REDUCTION:
            sprintf(string_buffer, "(130/131/132) Multicast listener query/report/reduction.");
            break;
        case ICMP6_ECHO_REQUEST:
            sprintf(string_buffer, "(8) Echo request.");
            break;
        default:
            sprintf(string_buffer, "(?) Unknown ICMP6 message.");
            break;
    }
    str_append_string(&packet_storage.icmp_type, string_buffer);
    get_frame_content(packet);
}

// gets information from IPv6 TCP packet
void ipv6_tcp_packet(const u_char *packet) {
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr*)(packet + SIZE_ETH_H + 40);

    sprintf(string_buffer, "%hu", ntohs(tcp_header->th_sport));
    str_append_string(&packet_storage.port_src, string_buffer);
    sprintf(string_buffer, "%hu", ntohs(tcp_header->th_dport));
    str_append_string(&packet_storage.port_dst, string_buffer);
    get_frame_content(packet);
}

// gets information from IPv6 UDP packet
void ipv6_udp_packet(const u_char *packet) {
    struct udphdr *udp_header;
    const uint8_t tcp_header_length = 8;

    udp_header = (struct udphdr*)(packet + SIZE_ETH_H + IPV6_HEADER_SIZE);

    sprintf(string_buffer, "%hu", ntohs(udp_header->uh_sport));
    str_append_string(&packet_storage.port_src, string_buffer);
    sprintf(string_buffer, "%hu", ntohs(udp_header->uh_dport));
    str_append_string(&packet_storage.port_dst, string_buffer);

    uint16_t payload_size = ntohs(udp_header->uh_ulen) - tcp_header_length;
    packet_storage.payload_size = payload_size;
    get_frame_content(packet);
}

// base function during IPv6 packet capture
// based on packet protocol decides how to unfold the packet
int ipv6_packet(const u_char *packet) {
    struct ip6_hdr *ipv6_header;
    ipv6_header = (struct ip6_hdr*)(packet + packet_storage.dl_header_size);

    inet_ntop(AF_INET6, &(ipv6_header->ip6_src), string_buffer, INET6_ADDRSTRLEN);
    str_append_string(&packet_storage.mac6_src, string_buffer);
    inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), string_buffer, INET6_ADDRSTRLEN);
    str_append_string(&packet_storage.mac6_dst, string_buffer);

    uint8_t ip6_next_header_type = ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    uint16_t payload_size = ntohs(ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen);
    packet_storage.frame_length += payload_size + IPV6_HEADER_SIZE;

    switch (ip6_next_header_type) {
        case IPPROTO_TCP:
            str_append_string(&packet_storage.protocol, "TCP");
            ipv6_tcp_packet(packet);
            break;
        case IPPROTO_UDP:
            str_append_string(&packet_storage.protocol, "UDP");
            ipv6_udp_packet(packet);
            break;
        case IPPROTO_ICMPV6:
            str_append_string(&packet_storage.protocol, "ICMP");
            ipv6_icmp_packet(packet);
            break;
        default:
            str_append_string(&packet_storage.protocol, "Unknown IPv6 protocol");
            break;
    }
    return 0;
}

// assigns time to packet storage in specified time format
void get_time_from_pkthdr(const struct pcap_pkthdr *header) {
    char time_string[40] = {0};
    struct tm* broken_down_time = localtime(&header->ts.tv_sec);
    strftime(time_string, sizeof (time_string), "%Y-%m-%dT%H:%M:%S", broken_down_time);
    long milliseconds = header->ts.tv_usec / 1000;
    sprintf(string_buffer, "%s.%03ld", time_string, milliseconds);
    str_append_string(&packet_storage.time_stamp, string_buffer);

    char utc_time_zone[10] = {0};
    strftime(utc_time_zone, sizeof(time_string), "%z", broken_down_time);

    for (int i = 0; i < 5; i++) {
        str_append_char(&packet_storage.time_stamp, utc_time_zone[i]);
        if (i == 2) str_append_char(&packet_storage.time_stamp, ':');
    }
}

// prints desired packet information from packet storage
void print_packet() {
    printf("timestamp:      %s\n", packet_storage.time_stamp.ptr);
    printf("eth type:       %s\n", packet_storage.eth_type.ptr);
    if (!strcmp(packet_storage.eth_type.ptr, "ARP")) {
        printf("arp protocol:   %s\n", packet_storage.arp_protocol_type.ptr);
        printf("arp operation:  %s\n", packet_storage.arp_operation.ptr);
    } else {
        printf("protocol:       %s\n", packet_storage.protocol.ptr);
    }
    printf("src MAC:        %s\n", packet_storage.mac_src.ptr);
    printf("dst MAC:        %s\n", packet_storage.mac_dst.ptr);
    if (!strcmp(packet_storage.eth_type.ptr, "IPv6")) {
        printf("src MAC(IPv6):  %s\n", packet_storage.mac6_src.ptr);
        printf("dst MAC(IPv6):  %s\n", packet_storage.mac6_dst.ptr);
    }
    printf("frame length:   %lu\n", packet_storage.frame_length);
    if (strcmp(packet_storage.eth_type.ptr, "IPv6") != 0) {
        printf("src IP:         %s\n", packet_storage.ip_src.ptr);
        printf("dst IP:         %s\n", packet_storage.ip_dst.ptr);
    }
    if (!strcmp(packet_storage.protocol.ptr, "TCP") || !strcmp(packet_storage.protocol.ptr, "UDP")) {
        printf("src port:       %s\n", packet_storage.port_src.ptr);
        printf("dst port:       %s\n", packet_storage.port_dst.ptr);
        printf("payload size:   %lu\n", packet_storage.payload_size);
    }
    if (!strcmp(packet_storage.protocol.ptr, "ICMP")){
        printf("ICMP type:      %s\n", packet_storage.icmp_type.ptr);
    }
    printf("\n%s", packet_storage.frame_content.ptr);
    printf("\n");
    fflush(stdout);
}

// filters desired packets specified by input flags
void check_and_print_packet() {
    bool passed = false;
    // filter packets that are not supposed to be written out
    if (!strcmp(packet_storage.protocol.ptr, "TCP") && tcp_flag) passed = true;
    if (!strcmp(packet_storage.protocol.ptr, "UDP") && udp_flag) passed = true;
    if (!strcmp(packet_storage.eth_type.ptr, "ARP") && arp_flag) passed = true;
    if (!strcmp(packet_storage.protocol.ptr, "ICMP") && icmp_flag) passed = true;
    if (strcmp(packet_storage.eth_type.ptr, "IPv6") != 0 && ipv6_flag) passed = false;
    if (strcmp(packet_storage.eth_type.ptr, "IPv4") != 0 && ipv4_flag) passed = false;
    if (port_n_is_set) {
        if (strcmp(packet_storage.port_dst.ptr, port_n) != 0 && strcmp(packet_storage.port_src.ptr, port_n) != 0) {
            passed = false;
        }
    }
    // packet did not pass
    if (!passed) {
        return;
    }
    // decrement number of desired packets to be printed out
    packet_n--;
    print_packet();
}

// handler function for pcap_loop
// base function during packet capture, decides what to do with the packet
// breaks pcap_loop if specified number of packets were printed out
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth_header;
    uint16_t eth_type;

    get_time_from_pkthdr(header);

    // define ethernet header
    eth_header = (struct ether_header*)(packet);

    // print source, destination and get ether type
    ether_info(eth_header, &eth_type);

    switch (eth_type) {
        case ETH_P_IP:
            str_append_string(&packet_storage.eth_type, "IPv4");
            ipv4_packet(packet);
            break;
        case ETH_P_IPV6:
            str_append_string(&packet_storage.eth_type, "IPv6");
            ipv6_packet(packet);
            break;
        case ETH_P_ARP:
            str_append_string(&packet_storage.eth_type, "ARP");
            arp_packet(packet);
            break;
        default:
            str_append_string(&packet_storage.eth_type, "Unknown ethernet header type");
            break;
    }

    // break if we found given number of packets we were looking for
    if (packet_n == 0) {
        pcap_breakloop(handle);
        return;
    }

    check_and_print_packet();
    // clear and allocate new storage for upcoming packet
    reinit_packet_storage_struct();
}

int main(int argc, char *argv[]) {
    init_packet_storage_struct();
    *interface_name = 0;
    int result = process_arguments(argc, argv);
    if (result != 0) {
        return result;
    }

    signal(SIGINT, stop_capture);
    signal(SIGTERM, stop_capture);

    printf("Starting...\n\n");

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

    stop_capture(0);
    return 0;
}
