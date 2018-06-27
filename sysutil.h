#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_server(const char *host, unsigned short port);
int accept_timeout(int listenfd, struct sockaddr_in *addr, unsigned int wait_seconds);
ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, void *buf, size_t n);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);


#endif /*_SYS_UTIL_H_*/