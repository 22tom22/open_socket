#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <ctype.h>
#include <errno.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#define LLDP_MULTICAST_ADDR                \
    {                                      \
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e \
    }

struct eth_hdr
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t eth_type;
} __attribute__((packed));

int GetIf(char *ifname)
{
    int sock_r;
    struct ifreq ifr;

    // get the interface index of the of the selected interface
    if ((sock_r = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) < 0)
    {
        perror("Errore nell'apertura del socket:");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    if (ioctl(sock_r, SIOCGIFINDEX, &ifr) != 0)
    {
        perror("Errore nell'acquisire l'interfaccia");
        close(sock_r);
        return -1;
    }

    close(sock_r);

    return ifr.ifr_ifindex;
}

int OpenSocket(char *ifname)
{
    int sock_r, if_index, buflen;
    struct sockaddr_ll sa;
    struct ifreq ifr;
    // struct iphdr *ip_hdr;
    const char lldpaddr[] = LLDP_MULTICAST_ADDR;

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_r < 0)
    {
        printf("Error in socket...\n");
        return -1;
    }

    // bind socket
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = 0;
    sa.sll_ifindex = if_index;

    if (bind(sock_r, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("Error in binding...\n");
        close(sock_r);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    memcpy(&ifr.ifr_hwaddr.sa_data, lldpaddr, ETH_ALEN);

    unsigned char *buffer = (unsigned char *)malloc(65536); // to receive data
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    // Receive a network packet and copy in to buffer
    buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
    if (buflen < 0)
    {
        printf("error in reading recvfrom function\n");
        return -1;
    }

    struct eth_hdr *eth = (struct eth_hdr *)(buffer);
    printf("\nEthernet Header\n");
    printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
    printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
    printf("\t|-Protocol : %d\n", eth->eth_type);

    unsigned short iphdrlen;
    struct iphdr *ip_hdr = (struct iphdr *)(buffer + sizeof(struct eth_hdr));

    // memset(&source, 0, sizeof(source));
    // source.sin_addr.s_addr = ip_hdr->saddr;
    // memset(&dest, 0, sizeof(dest));
    // dest.sin_addr.s_addr = ip_hdr->daddr;

    printf("\t|-Version : %d\n", (unsigned int)ip_hdr->version);
    printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n", (unsigned int)ip_hdr->ihl, ((unsigned int)(ip_hdr->ihl)) * 4);
    printf("\t|-Type Of Service : %d\n", (unsigned int)ip_hdr->tos);
    printf("\t|-Total Length : %d Bytes\n", ntohs(ip_hdr->tot_len));
    printf("\t|-Identification : %d\n", ntohs(ip_hdr->id));
    printf("\t|-Time To Live : %d\n", (unsigned int)ip_hdr->ttl);
    printf("\t|-Protocol : %d\n", (unsigned int)ip_hdr->protocol);
    printf("\t|-Header Checksum : %d\n", ntohs(ip_hdr->check));

    // printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
    // printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));

    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    /* getting actual size of IP header*/
    iphdrlen = ip->ihl * 4;
    /* getting pointer to udp header*/
    struct udphdr *udp = (struct udphdr *)(buffer + iphdrlen + sizeof(struct ethhdr));

    printf("\t|-Source Port : %d\n", ntohs(udp->source));
    printf("\t|-Destination Port : %d\n", ntohs(udp->dest));
    // printf("\t|-UDP Length : %d\n", ntohs(udp->len));
    printf("\t|-UDP Checksum : %d\n", ntohs(udp->check));

    unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

    int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

    for (int ii = 0; ii < remaining_data; ii++)
    {
        if (ii != 0 && ii % 16 == 0)
            printf("\n");
        printf(" %.2X ", data[ii]);
    }
    printf("\n-------------------------------------------------------------------------------\n\n");
}

/**
 * Main program for execution
 */
int main(int argc, char **argv)
{
    int x;

    GetIf("enp0s3");

    for (x = 1;; x++)
    {
        OpenSocket("enp0s3");
        sleep(1);
    }
}