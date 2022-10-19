#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */

struct ethhdr
{
    unsigned char  h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    __be16 h_proto;
}__attribute__((packet));

int
OpenRAWSocket(char *ifname)
{
    int sock_r;

    sock_r = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_r < 0)
    {
        printf("error in socket\n");
        return -1;
    }
}

int RecvPacket(char *ifname)
{
    int sock_r;

    if ((sock_r = OpenRAWSocket(ifname)) < 0)
    {
        printf("Errore nell'apertura del socket\n");
        return -1;
    }

    unsigned char *buffer = (unsigned char *)malloc(65536); // to receive data
    memset(buffer, 0, 65536);
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    // Receive a network packet and copy in to buffer
    int buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
    if (buflen < 0)
    {
        printf("error in reading recvfrom function\n");
        return -1;
    }

    struct ethhdr *eth = (struct ethhdr *)(buffer);
    printf("\nEthernet Header\n");
    printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("\t|-Protocol : %d\n", eth->h_proto);
}