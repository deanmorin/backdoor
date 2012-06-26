#include <syslog.h>
#include "clntsrvr.h"
#include "pkthdr.h"
#include "network.h"
#include "util.h"

void client(char *clnt_name, char *srvr_name, char *buf, size_t buflen)
{
    char dgram[DGRAM_LEN];
    int sd;

    int count = 0;
    unsigned int i;

    struct ip_header *iph = (struct ip_header*) dgram;
    struct udp_header *udph = (struct udp_header *)
            (dgram + sizeof(struct ip_header));
    struct pseudo_header pseudoh;
    
    struct sockaddr_in sin;
    struct sockaddr_in din;

    uint16_t initid;

    /* byte order changed to make encoding calculations easier */
    initid = htons(buflen);

    memset(dgram, 0, DGRAM_LEN);
    memset((char *) &sin, 0, sizeof(struct sockaddr_in));
    memset((char *) &din, 0, sizeof(struct sockaddr_in));

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    sin.sin_port = htons(port_from_date());
    din.sin_port = htons(DST_PORT);
    sin.sin_addr.s_addr = inet_addr(clnt_name);
    din.sin_addr.s_addr = inet_addr(srvr_name);

    ip_version(iph, IP_VERSION);
    ip_hdrlen(iph, IP_HDR_LEN);
    iph->tos = 0;
    iph->length = htons(DGRAM_LEN);
    iph->id = htons(initid);   
    ip_flags(iph, IP_DONTFRAG);
    ip_offset(iph, 0);
    /*iph->_flags_offset = 0x40;*/
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->srcip = inet_addr(clnt_name);
    iph->dstip = inet_addr(srvr_name);

    udph->srcport = htons(port_from_date());
    udph->dstport = htons(DST_PORT);
    udph->length = htons(sizeof(struct udp_header));
    /*udph->checksum = trans_chksum((uint16_t *) udph, (uint16_t *) &pseudoh,*/
            /*0, NULL, 0);*/

    fill_pseudo_hdr(&pseudoh, iph, sizeof(struct udp_header)); /* + data length */

    iph->checksum = chksum((uint16_t *) dgram, IP_HDR_LEN);

    sd = raw_socket();

/*#ifdef DEBUG*/
    /*printf("srcip:    %s\n", inet_ntoa(sin.sin_addr));*/
    /*printf("srcport:  %d\n", ntohs(sin.sin_port));*/
    /*printf("dstip:    %s\n", inet_ntoa(din.sin_addr));*/
    /*printf("dstport:  %d\n", ntohs(din.sin_port));*/
/*#endif*/

    /* initial ID that all encoding will be based off of (also length of msg) */
    send_encoded(sd, dgram, ntohs(iph->length), &din);
    sleep(1);
    ip_flags(iph, 0);

    for (i = 0; i < buflen; i++)
    {
        char c = buf[i];

        /* send half a char at a time */
        int fhalf = c >> 4;
        int shalf = c & 0xF;

        iph->id = htons(initid + 0x10 * count++ + fhalf + 1);
        send_encoded(sd, dgram, ntohs(iph->length), &din);
        iph->id = htons(initid + 0x10 * count++ + shalf + 1);
        send_encoded(sd, dgram, ntohs(iph->length), &din);
        syslog(LOG_INFO, "%u datagrams sent", i);
    }
    syslog(LOG_INFO, "all datagrams sent");
    close(sd);
}

int raw_socket()
{
    int sd;
    int on = 1;

    if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0)
    {
        int err = sock_error("socket()", 0);
        fprintf(stderr, "> You need root privileges to run this program.\n");
        exit(err);
    }
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(int)) < 0)
    {
        exit(sock_error("setsockopt()", 0));
    }
    return sd;
}

void send_encoded(int sd, char *dgram, uint16_t len, struct sockaddr_in *din) 
{
    if (sendto(sd, dgram, len, 0, (struct sockaddr *) din, 
            sizeof(struct sockaddr_in)) < 0)
    {
        exit(sock_error("sendto()", 0));
    }
    usleep(100);
}
