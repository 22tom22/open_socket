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
#include <linux/if_vlan.h>
#include <netinet/if_ether.h>

#ifdef TP_STATUS_VLAN_VALID
#define VLAN_VALID(hdr, hv) ((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & TP_STATUS_VLAN_VALID))
#endif

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

struct eth_8021Q_hdr
{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t vlan_proto;
    uint16_t vlan_tci;
    uint16_t encapsulated_proto;
} __attribute__((packed));

// Header Ethernet
struct sniff_ethernet
{
    unsigned char ether_dhost[ETHER_ADDR_LEN]; // destination host address
    unsigned char ether_shost[ETHER_ADDR_LEN]; // host address
    unsigned short ether_type;
};

// decoded packet information
struct igmp_proto_info
{
    uint8_t igmp_version;
    uint8_t type;
    char type_name[30];

    struct in_addr mc_group; // multicast group address (bin)
    char mc_group_str[18];   // multicast group address (str)
};

struct pkt_info
{
    // l2 header info
    uint8_t src_mac[ETH_ALEN];
    uint8_t dst_mac[ETH_ALEN];
    char src_mac_str[20];
    char dst_mac_str[20];
    uint16_t l3_protocol;
    char l3_protocol_name[20];

    // l3 header info
    struct in_addr src;
    struct in_addr dst;
    char src_str[18];
    char dst_str[18];
    uint8_t l4_protocol;
    uint8_t l4_protocol_name[20];

    struct igmp_proto_info igmp_proto_info;
};

struct lldp_info
{
    int chassis_id_length;
    int chassis_id_subtype;
    int *chassis_id;

    int port_id_subtype;
    int *port_id;
    int *port_description;

    int ttl;
    int capabilities;

    char *system_name;
    char *system_description;

    int mgmt_addr_type;
    int mgmt_addr_length;
    int *mgmt_addr;
};

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
    uint8_t packet[2048];
    struct sockaddr_ll sa;
    struct ifreq ifr;
    // struct iphdr *ip_hdr;
    const char lldpaddr[] = LLDP_MULTICAST_ADDR;

    sock_r = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
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

    // set promiscuous mode
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ioctl(sock_r, SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags |= IFF_PROMISC;
    ioctl(sock_r, SIOCSIFFLAGS, &ifr);
    memcpy(&ifr.ifr_hwaddr.sa_data, lldpaddr, ETH_ALEN);

    return sock_r;
}

int ReadSocket(int sock_r)
{
    int nn, i;
    uint8_t packet[2048];
    struct iovec iov = {.iov_base = packet, .iov_len = 2048};
    struct cmsghdr *cmsg_ptr;
    unsigned char *pt_ether;
    const struct sniff_ethernet *ethernet;

    union
    {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;

    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = &cmsg_buf, .msg_controllen = sizeof(cmsg_buf)};

    // open a raw socket binded to the tx interface
    if ((sock_r = OpenSocket("enp0s3")) < 0)
    {
        printf("Error opening raw socket\n");
        return -1;
    }

    int one = 1;

    if (setsockopt(sock_r, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0)
    {
        perror("Error setting PACKET_AUXDATA");
        close(sock_r);
        return -1;
    }

    while ((nn = recvmsg(sock_r, &msg, 0)) >= 0)
    {

        unsigned char *buffer = (unsigned char *)malloc(65536); // to receive data
        memset(buffer, 0, 65536);
        struct sockaddr saddr;
        int saddr_len = sizeof(saddr);

        int buflen;
        buflen = recvfrom(sock_r, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        printf("buflen length: %d\n", buflen);

        struct eth_hdr *eth = (struct eth_hdr *)(buffer);
        printf("\nEthernet Header\n");
        printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);
        printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->dst[0], eth->dst[1], eth->dst[2], eth->dst[3], eth->dst[4], eth->dst[5]);
        printf("\t|-Protocol : %d\n", eth->eth_type);

        struct eth_8021Q_hdr *eth_802 = (struct eth_8021Q_hdr *)(buffer);
        printf("\t|-Vlan Proto : 0x%x\n", ntohs(eth_802->vlan_proto));
        printf("\t|-Vlan TCI : %d\n", eth_802->vlan_tci);
        printf("\t|-Encapsulated Proto : 0x%x\n", ntohs(eth_802->encapsulated_proto));

        struct igmp_proto_info *igmp = (struct igmp_proto_info *)(buffer);
        printf("\t|-Igmp Type : %d\n", igmp->type);
        printf("\t|-Igmp Type Name : %s\n", igmp->type_name);

        struct pkt_info *pkt = (struct pkt_info *)(buffer);
        printf("\t|-l3 Proto : %d\n", pkt->l3_protocol);
        // printf("\t|-l3 Proto Name: %s\n", pkt->l3_protocol_name);
        printf("\t|-l4 Proto : %d\n", pkt->l4_protocol);
        printf("\t|-l4 Proto Name: %hhn\n", pkt->l4_protocol_name);

        /*
        struct lldp_info *lldp = (struct lldp_info *)(buffer);
        printf("\t|- Chassis ID : %ls\n", lldp->chassis_id);
        printf("\t|- Mgmt Address : %ls\n", lldp->mgmt_addr);
        printf("\t|- Mgmt Address Type : %d\n", lldp->mgmt_addr_type);
        printf("\t|-Port ID : %ls\n", lldp->port_id);
        printf("\t|- System Name : %s\n", lldp->system_name);
        printf("\t|- System Description:  %s\n", lldp->system_description);
        printf("\t|- Port Description : %ls\n", lldp->port_description);
        */

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
        printf("\t|-UDP Checksum : %d\n", ntohs(udp->check));

        unsigned char *data = (buffer + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

        int remaining_data = buflen - (iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));

        /*
        for (int ii = 0; ii < remaining_data; ii++)
        {
            if (ii != 0 && ii % 16 == 0)
                printf("\n");
            printf(" %.2X ", data[ii]);
        }
        */

        printf("Eccomi\n");
        for (cmsg_ptr = CMSG_FIRSTHDR(&msg); cmsg_ptr; cmsg_ptr = CMSG_NXTHDR(&msg, cmsg_ptr))
        {
            printf("Sono dentro il for\n");
            struct tpacket_auxdata *aux_ptr;

            if ((cmsg_ptr->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))) || (cmsg_ptr->cmsg_level != SOL_PACKET) || (cmsg_ptr->cmsg_type != PACKET_AUXDATA))
            {
                continue;
            }

            printf("Sono riuscito a passare qua\n");

            aux_ptr = (struct tpacket_auxdata *)CMSG_DATA(cmsg_ptr);

            printf("Vado avanti di un passo\n");

            /*
            if (!VLAN_VALID(aux_ptr, aux_ptr))
            {
                printf("Sono dentro l'if della VLAN\n");
                continue;
            }
            */

            printf("Vado avanti di un ulteriore passo\n");

            if (aux_ptr->tp_vlan_tci == 0)
            {
                printf("TAG\n");
            }
            else
            {
                printf("No TAG 0x%x\n", (aux_ptr->tp_vlan_tci) & 0x0fff);
            }
            printf("Ho finito con il for\n");
        }

        printf("\n-------------------------------------------------------------------------------\n\n");
        sleep(2);
    }
}

/**
 * Main program for execution
 */
int main(int argc, char **argv)
{
    int sock_r;

    GetIf("enp0s3");
    OpenSocket("enp0s3");
    ReadSocket(sock_r);
}