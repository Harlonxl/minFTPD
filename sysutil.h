#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_server(const char *host, unsigned short port);
int accept_timeout(int listenfd, struct sockaddr_in *addr, unsigned int wait_seconds);
ssize_t readn(int fd, void *buf, size_t n);
ssize_t writen(int fd, const void *buf, size_t n);
ssize_t recv_peek(int sockfd, void *buf, size_t len);
ssize_t readline(int sockfd, void *buf, size_t maxline);
int getlocalip(char *ip);
int tcp_client(unsigned short port);
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds);
void send_fd(int sock_fd, int fd);
int recv_fd(const int sock_fd);
const char *statbuf_get_perms(struct stat *sbuf);
const char *statbuf_get_date(struct stat *sbuf);


#endif /*_SYS_UTIL_H_*/