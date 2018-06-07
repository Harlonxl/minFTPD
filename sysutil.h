#ifndef _SYS_UTIL_H_
#define _SYS_UTIL_H_

#include "common.h"

int tcp_server(const char *host, unsigned short port);
int accept_timeout(int listenfd, struct sockaddr_in *addr, unsigned int wait_seconds);

#endif /*_SYS_UTIL_H_*/