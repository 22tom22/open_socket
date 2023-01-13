#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

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

#define TRUE = 0
#define FALSE = 1

#ifdef TP_STATUS_VLAN_VALID
#define VLAN_VALID(hdr, hv) ((hv)->tp_vlan_tci != 0 || ((hdr)->tp_status & TP_STATUS_VLAN_VALID))
#endif

/* TLV Types*/
#define END_OF_LLDPDU_TLV 0
#define CHASSIS_ID_TLV 1
#define PORT_ID_TLV 2
#define PORT_DESCRIPTION_TLV 4
#define SYSTEM_NAME_TLV 5

/* Chassis ID TLV Subtypes*/
#define CHASSIS_ID_CHASSIS_COMPONENT 1
#define CHASSIS_ID_INTERFACE_ALIAS 2
#define CHASSIS_ID_PORT_COMPONENT 3
#define CHASSIS_ID_MAC_ADDRESS 4
#define CHASSIS_ID_NETWORK_ADDRESS 5

// Low level packet habndling
#ifndef ETHERTYPE_LLDP
#define ETHERTYPE_LLDP 0x88cc
#endif
#define ETHERTYPE_TTCMP 0x895
#define ETHERTYPE_8021Q 0x8100

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

struct lldp_tlv
{
    uint8_t type;
    uint16_t length;
    uint8_t *info;
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

struct ttdp_info
{

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
            // printf("Protocol: 0x0%x\n", htons(eth_hdr->eth_type));
        }
        else if (TagVlan >= 0)
        {
            printf("Pacchetto con tag: 0x%x\n", TagVlan);
            // printf("Protocol: 0x%x\n", htons(eth_hdr->eth_type));

            HELLO_decodePacket(..., packet, 2048);
            DecodeTLV(..., 2048, ...);
        }

        printf("----------------------------------------------------------\n\n");
    }
}

/**
 * Fills generic TLV structure (strcut lldp_tlv) with the supplied data
 * decoding the type and length fields
 *
 * @param *data Pointer to the data buffer (recived data)
 * @param *size Pointer to the buffer size; updated subtracing the consumed data length
 * @param **tlv Pointer where to return the allocated TLV structure; the pointed value
 *              must be NULL. It's suggested to free the returned data using FreeLLDPtlv()
 * @return The consumed size (0 in case of error)
 */
uint DecodeTLV(uint8_t const *data, uint *size, struct lldp_tlv **tlv)
{
    uint decoded_bytes = 0;

    assert(size);
    assert(tlv && !*tlv);

    if (data && *size)
    {
        // Decode the tLV header
        uint16_t type, length;
        uint16_t tlv_header;

        memcpy(&tlv_header, data, sizeof(tlv_header));
        type = ntohs(tlv_header) >> 9;
        length = ntohs(tlv_header) & 0x01FF;

        if (*size >= length + 2)
        {
            // Allocate the decoded TLV
            *tlv = calloc(tlv_header, length); // >> 9;
            (*tlv)->type = type;
            (*tlv)->type = length;

            // attach a copy of the payload
            if (length)
            {
                (*tlv)->info = memcpy(data + 2, data +1, length);
            }

            // Update data size with consumed length
            decoded_bytes = length + 2;
            *size -= decoded_bytes;
        }
        else
        {
            printf("Malformed TLV(type %u): length is 2 + %u but available size is %u\n", type, length, *size);
        }
    }

    return decoded_bytes;
}

/**
 * @brief handle the recepition of a TTDP HELLO packet
 *
 * This is a standard LLDP packet containing a specific TLV
 *
 * @param tinfo A refernce to the global TTDP information structure
 * @param packet Points to the recived packet
 * @param size Is the size of the recived packet
 * @return FALSE in case of any decoding error; TRUE otherwise
 */
static unsigned char HELLO_decodePacket(struct ttdp_info *tinfo, uint8_t const *packet, int32_t size)
{
    static char const lldpaddr[] = LLDP_MULTICAST_ADDR;

    uint8_t const *p_packet = packet;
    struct eth_hdr *hdr;
    unsigned char tlv_end = 1;
    unsigned char bad_frame = 1;

    struct lldp_tlv *tlv = NULL;
    uint tlv_num = 0;
    uint8_t mandatory_tlv_mask = 0x00;

    hdr = (struct eth_hdr *)packet;

    while ((size > 0) && !tlv_end)
    {
        p_packet += DecodeTLV(p_packet, (uint *)&size, &tlv);
        if (tlv)
        {
            tlv_num++;

            if ((tlv_num < 4) && (tlv_num != tlv->type))
            {
                bad_frame = 0;
            }
            else if ((tlv_num > 3) && ((tlv->type == 1) || (tlv->type == 2) || (tlv->type == 3)))
            {
                bad_frame = 0;
            }

            if (tlv->type < 4)
            {
                mandatory_tlv_mask |= (0x1 << tlv->type);
            }

            /*
            if (!HELLO_decodeTLV(tlv))
            {
                bad_frame = 0;
            }
            else if (tlv->type == END_OF_LLDPDU_TLV)
            {
                tlv_end = 0;
            }
            */

           if(tlv->type == END_OF_LLDPDU_TLV)
           {
            tlv_end = 0;
           }

            if (bad_frame)
            {
                printf("Malformed TTDP HELLO packet\n");
            }

            if (!bad_frame)
            {
                if (!tlv_end)
                {
                    printf("Malformed TTDP HELLO (missing END TLV)\n");
                    bad_frame = 0;
                }
                else if (mandatory_tlv_mask != 0x0f)
                {
                    printf("Missing mandatory TTDP HELLO TLV / Packet Discarded\n");
                }
                else if (size > 0)
                {
                    printf("Extra bytes after END TLV in TTDP HELLO packet\n");
                }
            }

            return !bad_frame;
        }
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
