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

/* Funzione che seleziona l-interfaccia da cui catturare i pacchetti */
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

/* Funizone per apertura e bind di un socket */
int OpenSocket(char *ifname)
{
    int sock_r, if_index;
    // uint8_t packet[2048];
    struct sockaddr_ll sa;
    struct ifreq ifr;
    // const char lldpaddr[] = LLDP_MULTICAST_ADDR;

    // get kernel interface index
    if ((if_index = GetIf(ifname)) < 0)
    {
        printf("Error getting %s interface index\n", ifname);
        return -1;
    }

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
    // memcpy(&ifr.ifr_hwaddr.sa_data, lldpaddr, ETH_ALEN);

    return sock_r;
}

/* Funzione che stampa un indirizzo MAC */
void PrintMac(uint8_t *addr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

/* Funzione che ritorna il valore del tag se il pacchetto contiene il tag vlan oppure -1 se il pacchetto nopn contiene il tag vlan*/
int GetTag(struct msghdr *msg)
{
    struct cmsghdr *cmsg_ptr;

    for (cmsg_ptr = CMSG_FIRSTHDR(msg); cmsg_ptr; cmsg_ptr = CMSG_NXTHDR(msg, cmsg_ptr))
    {
        struct tpacket_auxdata *aux_ptr;

        if ((cmsg_ptr->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))) || (cmsg_ptr->cmsg_level != SOL_PACKET) || (cmsg_ptr->cmsg_type != PACKET_AUXDATA))
            continue;

        aux_ptr = (struct tpacket_auxdata *)CMSG_DATA(cmsg_ptr);

        if (aux_ptr->tp_vlan_tci == 0)
        {
            return -1;
        }
        else
        {
            return (aux_ptr->tp_vlan_tci) & 0x0fff;
        }
    }
}

/* Funzione principale */
int CaptureInterface(char *ifname)
{
    int sock_r;
    uint8_t packet[2048];
    struct sockaddr_ll packet_info;
    int packet_info_size = sizeof(packet_info);
    int nn, decoded, i;
    struct eth_hdr *eth_hdr;
    struct iphdr *ip_hdr;
    struct pkt_info p;
    int one = 1;
    int TagVlan;

    struct iovec iov;
    struct cmsghdr *cmsg_ptr;
    union
    {
        struct cmsghdr cmsg;
        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;

    struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1, .msg_control = &cmsg_buf, .msg_controllen = sizeof(cmsg_buf)};

    bzero(&p, sizeof(p));

    eth_hdr = (struct eth_hdr *)packet;
    ip_hdr = (struct iphdr *)(packet + sizeof(struct ethhdr));

    // open a raw socket binded to the tx interface
    if ((sock_r = OpenSocket(ifname)) < 0)
    {
        printf("Error opening raw socket\n");
        return -1;
    }

    if (setsockopt(sock_r, SOL_PACKET, PACKET_AUXDATA, &one, sizeof(one)) < 0)
    {
        perror("Error setting PACKET_AUXDATA");
        close(sock_r);
        return -1;
    }

    iov.iov_base = packet;
    iov.iov_len = 2048;
    msg.msg_iov = &iov;

    while ((nn = recvmsg(sock_r, &msg, 0)) >= 0)
    {
        printf("Pacchetto ricevuto\n");
    
        /* catturo il MAC sorgente e di destinazione dall'header ETHERNET */
        printf("    Src MAC: ");
        PrintMac(eth_hdr->src);
        printf("\n");

        printf("    Dst MAC: ");
        PrintMac(eth_hdr->dst);     
        printf("\n");

        TagVlan = GetTag(&msg);

        if (TagVlan < 0)
        {
            printf("Pacchetto non taggato\n");
            printf("Protocol: 0x0%x\n", htons(eth_hdr->eth_type));
        }
        else if (TagVlan >= 0)
        {
            printf("Pacchetto con tag: 0x%x\n", TagVlan);
            printf("Protocol: 0x%x\n", htons(eth_hdr->eth_type));
        }

        printf("----------------------------------------------------------\n\n");
    }
}

/**
 * Main program for execution
 */
int main(int argc, char **argv)
{
    if (argc > 1)
    {
        printf("Running TTDP test suite on port %s ...\n", argv[1]);
        CaptureInterface(argv[1]);
    }
    else
        printf("Syntax: %s <ifname>\n", argv[0]);
}
