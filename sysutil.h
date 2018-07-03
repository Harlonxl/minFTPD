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

int lock_file_read(int fd);
int lock_file_write(int fd);
int unlock_file(int fd);

long get_time_sec();
long get_time_usec();
void nano_sleep(double second);

void activate_oobinline(int fd);
void activate_sigurg(int fd);


#endif /*_SYS_UTIL_H_*/