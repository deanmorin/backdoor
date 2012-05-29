#include "pkthdr.h"
#include <arpa/inet.h>

int ip_version(struct ip_header *iph, const unsigned char version)
{
    if (!iph || version > 15)
    {
        return -1;
    }
    iph->_ver_hdrlen &= 0x0F;
    iph->_ver_hdrlen |= version << 4;
    return 0;
}

int ip_hdrlen(struct ip_header *iph, const unsigned char hdrlen)
{
    if (!iph || hdrlen > 15)
    {
        return -1;
    }
    iph->_ver_hdrlen &= 0xF0;
    iph->_ver_hdrlen |= hdrlen;
    return 0;
}

int ip_flags(struct ip_header *iph, const uint16_t flags)
{
    if (!iph || flags > 7)
    {
        return -1;
    }
    iph->_flags_offset &= 0xFF1F;
    iph->_flags_offset |= flags << 5;
    return 0;
}

int ip_offset(struct ip_header *iph, const uint16_t frag_offset)
{
    if (!iph || frag_offset > 8191)
    {
        return -1;
    }
    iph->_flags_offset &= 0x00E0;
    iph->_flags_offset |= htons(frag_offset);
    return 0;
}

int tcp_offset(struct tcp_header *tcph, const uint16_t offset)
{
    if (!tcph || offset > 15)
    {
        return -1;
    }
    tcph->_offset_flags &= 0xFF0F;
    tcph->_offset_flags |= offset << 4;
    return 0;
}

int tcp_flags(struct tcp_header *tcph, const uint16_t flags)
{
    if (!tcph || flags >= 512)
    {
        return -1;
    }
    tcph->_offset_flags &= 0x000F;
    tcph->_offset_flags |= htons(flags);
    return 0;
}
