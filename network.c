#include "network.h"
#include <errno.h>
#include <stdlib.h>


int clear_socket(int fd, char* buf, int bufsize)
{
    int	read = 0;
    int bytes_to_read = bufsize;
    char* bp = buf;

    while ((read = recv(fd, bp, bytes_to_read, 0)) < bytes_to_read)
    {
        if (read == -1)
        {
            if (errno != EAGAIN)
            {
                sock_error("recv()", 0);
                return -1;
            }
#ifdef DEBUG
            sock_error("recv()", 0);
#endif
            break;
        } 
        else if (!read)
        {
            return -1; 
        }
        bp += read;
        bytes_to_read -= read;
    }
    return bufsize - bytes_to_read;
}


int sock_error(const char* msg, int err)
{
    if (!err)
    {
        err = errno;
        perror(msg);
    }
    else
    {
        printf("%s", msg);
    }
    fprintf(stderr, "error type: ");

    switch (err)
    {
        case EAGAIN:        fprintf(stderr, "EAGAIN\n");        break;
        case EACCES:        fprintf(stderr, "EACCES\n");        break;
        case EADDRINUSE:    fprintf(stderr, "EADDRINUSE\n");    break;
        case EADDRNOTAVAIL: fprintf(stderr, "EADDRNOTAVAIL\n"); break;
        case EAFNOSUPPORT:  fprintf(stderr, "EAFNOSUPPORT\n");  break;
        case EALREADY:      fprintf(stderr, "EALREADY\n");      break;
        case EBADF:         fprintf(stderr, "EBADF\n");         break;
        case ECONNREFUSED:  fprintf(stderr, "ECONNREFUSED\n");  break;
        case EFAULT:        fprintf(stderr, "EFAULT\n");        break;
        case EHOSTUNREACH:  fprintf(stderr, "EHOSTUNREACH\n");  break;
        case EINPROGRESS:   fprintf(stderr, "EINPROGRESS\n");   break;
        case EINTR:         fprintf(stderr, "EINTR\n");         break;
        case EINVAL:        fprintf(stderr, "EINVAL\n");        break;
        case EISCONN:       fprintf(stderr, "EISCONN\n");       break;
        case ENETDOWN:      fprintf(stderr, "ENETDOWN\n");      break;
        case ENETUNREACH:   fprintf(stderr, "ENETUNREACH\n");   break;
        case ENOBUFS:       fprintf(stderr, "ENOBUFS\n");       break;
        case ENOTSOCK:      fprintf(stderr, "ENOTSOCK\n");      break;
        case EOPNOTSUPP:    fprintf(stderr, "EOPNOTSUPP\n");    break;
        case EPROTOTYPE:    fprintf(stderr, "EPROTOTYPE\n");    break;
        case ETIMEDOUT:     fprintf(stderr, "ETIMEDOUT\n");     break;
        case ECONNRESET:    fprintf(stderr, "ECONNRESET\n");    break;
        default:            fprintf(stderr, "%d (unknown)\n", err); 
    }
    return err;
}
