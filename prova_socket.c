#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>

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

    printf("Acquisizione interfaccia riucita...\n");

    close(sock_r);

    return ifr.ifr_ifindex;
}

int OpenSocket(char *ifname)
{
    int sock_r, if_index, buflen;
    struct sockaddr_ll sa;
    struct ifreq ifr;
    const char lldpaddr[] = LLDP_MULTICAST_ADDR;

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_r < 0)
    {
        printf("error in socket\n");
        return -1;
    }

    printf("Apertura socket riuscita...\n");

    // bind socket
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = 0;
    sa.sll_ifindex = if_index;

    if (bind(sock_r, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("Errore nel binding del socket ");
        close(sock_r);
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, ifname);
    memcpy(&ifr.ifr_hwaddr.sa_data, lldpaddr, ETH_ALEN);

    printf("Binding avvenuto correttamente...\n");

    unsigned char *buffer = (unsigned char *)malloc(65536); // to receive data
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    printf("sono qua...\n");

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
}

/**
 * Main program for execution
 */
int main(int argc, char **argv)
{
    GetIf("enp0s3");
    OpenSocket("enp0s3");
}