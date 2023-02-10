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

#include <uuid/uuid.h>

#define TRUE = 1
#define FALSE = 0

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

#define TIME_TO_LIVE_TLV 3
#define ORG_SPECIFIC_TLV 127
#define PORT_ID_AGENT_CIRCUIT_ID 6
#define TTDP_OUI "\x20\x0E\x95"
#define TTDP_HELLO_TLV 1 // TTDP HELLO specific TLV subtype
#define TTDP_PORTS 4
#define TTDP_HELLO_FAST 0x02

#define mac_copy(a, b) memcpy(a, b, ETH_ALEN)
#define mac_compare(a, b) memcmp(a, b, ETH_ALEN)
// #define mac_is_set(m) (m && (mac_compare(m, zero_mac) != 0))

typedef uint8_t MAC_ADDR[ETH_ALEN];

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

// TTDP Specific HELLO TLV definition
typedef struct HELLO_TLV
{
    uint8_t oui_id[3];
    uint8_t oui_subtype;
    uint16_t FCS;
    uint32_t version;
    uint32_t lifesign;
    uint32_t TopoCounter;
    uint8_t VendorInfo[32];
    uint8_t lines_status;
    uint8_t period;
    uint8_t source_id[6];
    uint8_t egress_line;
    uint8_t egress_direction;
    uint8_t InaugurationFlag;
    uint8_t remote_id[6];
    uint8_t cstUUID[16];
} __attribute__((packed)) HELLO_TLV;

// Direct neighbour descriptor. Data comes from TTDP HELLO packets recived from neighbours. Only one neighbour from each directions hould exist
typedef struct ttdp_neighbour
{
    MAC_ADDR mac;
    uint8_t *chassis_id;
    uint8_t *port_id;
    uint16_t ttl;
    char *system_name;

    char remote_lines[4];
    uint8_t remote_dir[4];

    char vendor_info[32];
    uint8_t lines;
    uint8_t inaug_flag;
    uuid_t cstUUID;
    MAC_ADDR source_id;
    MAC_ADDR remote_id;

    uint32_t etbTopoCnt;
} ETB_neighbour;

typedef struct ttdp_port
{
    char const *name;
    uint const line_idx;

    struct
    {
        uint8_t txFreq;
        uint32_t txSeqNum;
        uint32_t rxSeqNum;
        unsigned char txImmediate;

        uint32_t transitions;

        struct
        {
            uint8_t txFreq;
            uint32_t transitions;
        } remote;
    } hello;
} TTDPPort;

// This structure contains the information about this ETB. Some properties are statically defined while others comes from TTDP protocol frames
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
            (*tlv)->length = length;

            // attach a copy of the payload
            if (length)
            {
                (*tlv)->info = calloc(length, sizeof(char));
                memcpy((*tlv)->info, data + 2, length);
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

    printf("decoded bytes %d\n", decoded_bytes);

    return decoded_bytes;
}

/**
 * @brief Decode a single TTDP HELLO packet TLV
 *
 * Fills the TTDP information
 *
 * @param tlv Points to the tlv structure tp be decoded
 * @return 1 if the TLV was correctly decoded or 0 in case of error
 */
static unsigned char HELLO_decodeTLV(struct lldp_tlv const *tlv, ETB_neighbour *neighbour, TTDPPort *rx_port)
{
    unsigned char retval = 1;

    switch (tlv->type)
    {
    case END_OF_LLDPDU_TLV:
        break;

    case CHASSIS_ID_TLV:
        if (tlv->info[0] = CHASSIS_ID_MAC_ADDRESS)
        {
            if (!neighbour->chassis_id)
            {
                neighbour->chassis_id = (uint8_t *)calloc(1, tlv->length);
                memcpy(neighbour->chassis_id, &tlv->info[1], tlv->length - 1);
            }
        }
        break;

    case PORT_ID_TLV:
        if (tlv->info[0] == PORT_ID_AGENT_CIRCUIT_ID) // agent circuit-id subtype
        {
            if (!neighbour->port_id)
            {
                neighbour->port_id = (uint8_t *)calloc(1, tlv->length);
                memcpy(neighbour->port_id, &tlv->info[1], tlv->length - 1);
            }
        }
        break;

    case TIME_TO_LIVE_TLV:
    {
        uint16_t *ttl = (uint16_t *)&tlv->info[0];
        neighbour->ttl = ntohs(*ttl);
    }
    break;

    case SYSTEM_NAME_TLV:
        if (!neighbour->system_name)
        {
            neighbour->system_name = (char *)calloc(1, (tlv->length + 1));
            memcpy(neighbour->system_name, tlv->info, tlv->length);
        }
        break;

    case ORG_SPECIFIC_TLV:
    {
        HELLO_TLV *h = (HELLO_TLV *) tlv->info; 

        if (!memcmp(h->oui_id, TTDP_OUI, 3) && (h->oui_subtype == TTDP_HELLO_TLV))
        {
            uint16_t fcs = 0;
            uint32_t seq_num = ntohl(h->lifesign);

            // check for sequence number missing
            if (!rx_port->hello.rxSeqNum)
            {
                printf("%s: First TTDP HELLO packet (lifeSign recived %u)", rx_port->name, seq_num);
            }
            else if (rx_port->hello.rxSeqNum + 1u < seq_num)
            {
                printf("%s: Warning %u TTDP HELLO packets missed (lifeSign expected %u - recived %u)", rx_port->name, seq_num - (rx_port->hello.rxSeqNum + 1), rx_port->hello.rxSeqNum + 1, seq_num);
            }

            // save the sequence number of the recived frame
            rx_port->hello.rxSeqNum = seq_num;

            // get the Topology Counter
            neighbour->etbTopoCnt = ntohl(h->TopoCounter);

            // get vendor information
            memcpy(neighbour->vendor_info, h->VendorInfo, 32);

            // get remote lines status information
            neighbour->lines = h->lines_status;

            // check if neighour is asking for a fast HELLO
            if ((h->period == TTDP_HELLO_FAST))
            {
                rx_port->hello.txImmediate = 1;

                if (rx_port->hello.remote.txFreq != TTDP_HELLO_FAST)
                {
                    rx_port->hello.remote.transitions++;
                }
            }

            rx_port->hello.remote.txFreq = h->period;

            // associate remote line name and direction with the receiving port
            neighbour->remote_lines[rx_port->line_idx] = h->egress_line;
            neighbour->remote_dir[rx_port->line_idx] = h->egress_direction;

            // get inauguration inhibition flag
            neighbour->inaug_flag = h->InaugurationFlag;

            // check if there is something wrong with the source-id: it should not change suddenly without having zeroed i advange by timeout
            /*
            if (mac_is_set(neighbour->source_id) && mac_compare(neighbour->source_id, h->source_id))
            {
                printf("Warning source-id announced by neighbour doffers from the previous one!");
            }
            */

            // save source MAC address annouced by this neighbour
            mac_copy(neighbour->source_id, h->remote_id);

            // get the remote-ID
            mac_copy(neighbour->remote_id, h->remote_id);

            // get cstUUID
            uuid_copy(neighbour->cstUUID, h->cstUUID);
        }
    }
    break;

    default:
        retval = 0; // unkonown TLV
    }

    return retval;
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
static unsigned char HELLO_decodePacket(struct ttdp_info *tinfo, TTDPPort *rx_port, uint8_t const *packet, int32_t size)
{
    static char const lldpaddr[] = LLDP_MULTICAST_ADDR;

    // struct TTDPPort *rx_port = NULL;

    packet = packet + 6;
    uint8_t const *p_packet = packet;
    struct eth_hdr *hdr;
    unsigned char tlv_end = 0;
    unsigned char bad_frame = 0;
    ETB_neighbour *ttdp_neighbour = NULL;

    struct lldp_tlv *tlv = NULL;
    uint tlv_num = 0;
    uint8_t mandatory_tlv_mask = 0x00;

    hdr = (struct eth_hdr *)packet;

    // printf("%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x\n\n", *packet, *(packet + 1), *(packet + 2), *(packet + 3), *(packet + 4), *(packet + 5), *(packet + 6), *(packet + 7), *(packet + 8), *(packet + 9), *(packet + 10), *(packet + 11), *(packet + 12), *(packet + 13), *(packet + 14), *(packet + 15), *(packet + 16), *(packet + 17), *(packet + 18), *(packet + 19), *(packet + 20));

    while ((size > 0) && !tlv_end && !bad_frame)
    {
        tlv = NULL;
        p_packet += DecodeTLV(p_packet, (uint *)&size, &tlv);

        if (tlv)
        {
            tlv_num++;

            if ((tlv_num < 4) && (tlv_num != tlv->type))
            {
                bad_frame = 1;
            }
            else if ((tlv_num > 3) && ((tlv->type == 1) || (tlv->type == 2) || (tlv->type == 3)))
            {
                bad_frame = 1;
            }

            if (tlv->type < 4)
            {
                mandatory_tlv_mask |= (0x1 << tlv->type);
            }

            printf("\nInformation contains in tlv->type: %d\n", tlv->type);
            printf("Information contains in tlv->length: %d\n\n", tlv->length);

            if (!HELLO_decodeTLV(tlv, ttdp_neighbour, rx_port))
            {
                bad_frame = 1;
            }
            else if (tlv->type == END_OF_LLDPDU_TLV)
            {
                tlv_end = 1;
            }
        }
        else
        {
            bad_frame = 1;
        }

        if (bad_frame)
        {
            printf("Malformed TTDP HELLO packet\n");
        }
    }

    if (!bad_frame)
    {
        if (!tlv_end)
        {
            printf("Malformed TTDP HELLO (missing END TLV)\n");
            bad_frame = 1;
        }
        else if (mandatory_tlv_mask != 0x0f) // check that all mandatory TLV's has been recived
        {
            printf("Missing mandatory TTDP HELLO TLV / Packet Discarded\n");
            bad_frame = 1;
        }
        else if (size > 0)
        {
            printf("Extra bytes after END TLV in TTDP HELLO packet\n");
        }
    }

    return !bad_frame;
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

        printf("Valore di nn: %d\n", nn);

        if (TagVlan < 0)
        {
            printf("Pacchetto non taggato\n");
            printf("Protocol: 0x0%x\n", htons(eth_hdr->eth_type));
        }
        else if (TagVlan >= 0)
        {
            printf("Pacchetto con tag: 0x%x\n", TagVlan);
            printf("Protocol: 0x%x\n", htons(eth_hdr->eth_type));

            HELLO_decodePacket(NULL, *ifname, packet + sizeof(eth_hdr), 380);
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