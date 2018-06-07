#include "sysutil.h"

/**
 * tcp_server - 启动tcp服务器
 * @host：服务器IP地址或者服务器主机名
 * @port：服务器端口
 * 成功返回监听套接字
 */

int tcp_server(const char *host, unsigned short port) {
	int listenfd;
	if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		ERR_EXIT("tcp_server");
	}

	struct sockaddr_in serveraddr;
	memset(&serveraddr, 0, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;

	if (host != NULL) {
		if (inet_aton(host, &serveraddr.sin_addr) == 0) {
			struct hostent *hp;
			hp = gethostbyname(host);
			if (hp == NULL) {
				ERR_EXIT("gethostbyname");
			}
			serveraddr.sin_addr = *((struct in_addr*)hp->h_addr);
		}
	} else {
		serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	}

	serveraddr.sin_port = htons(port);

	int on = 1;
	if ((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on))) < 0) {
		ERR_EXIT("tcp_server");
	}

	if (bind(listenfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
		ERR_EXIT("tcp_server");
	}

	if (listen(listenfd, SOMAXCONN) < 0) {
		ERR_EXIT("tcp_server");
	}

	return listenfd;
}

/**
 * accept_timeout - 带超时的accept
 * @fd: 套接字
 * @addr: 输出参数，返回对方地址
 * @wait_seconds: 等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回已连接套接字，超时返回-1并且errno = ETIMEDOUT
 */
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds) {
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr);

	if (wait_seconds > 0) {
		fd_set accept_fdset;
		struct timeval timeout;
		FD_ZERO(&accept_fdset);
		FD_SET(fd, &accept_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			ret = select(fd + 1, &accept_fdset, NULL, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);

		if (ret == -1) {
			return -1;
		} else if (ret == 0) {
			errno = ETIMEDOUT;
			return -1;
		}
	}

	if (addr != NULL) {
		ret = accept(fd, (struct sockaddr*)addr, &addrlen);
	} else {
		ret = accept(fd, NULL, NULL);
	}

	if (ret == -1) {
		ERR_EXIT("accept");
	}

	return ret;

}

/**
 * readn - 读取指定长度的数据
 * @fd：套接字
 * @buf：存放数据的缓冲区
 * @n：读取的长度
 * 返回读取到的长度
 */
ssize_t readn(int fd, void *buf, size_t n) {
	int nleft = n;
	int nread;
	char *bufp = (char *)buf;
	while (nleft > 0) {
		if((nread = read(fd, bufp, nleft)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		else if (nread == 0) {
			return n - nleft;
		}
		nleft -= nread;
		bufp += nread;
	}
	return n;
}

/**
 * writen - 写入指定长度的数据
 * @fd：套接字
 * @buf：写入数据的缓冲区
 * @n：写入的长度
 * 返回写入的长度
 */
ssize_t writen(int fd, void *buf, size_t n) {
	int nleft = n;
	int nwrite;
	char *bufp = (char *)buf;
	while (nleft > 0) {
		if((nwrite = write(fd, bufp, nleft)) < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		else if (nwrite == 0) {
			return n - nleft;
		}
		nleft -= nwrite;
		bufp += nwrite;
	}
	return n;
}

ssize_t recv_peek(int sockfd, void *buf, size_t len) {
	while (1) {
		int ret = recv(sockfd, buf, len, MSG_PEEK);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		return ret;
	}
}

/**
 * readline - 读取一行
 * @sockfd：套接字
 * @buf：读入的缓冲区
 * @maxline：最大字符数
 * 返回实际读取的字符数
 */
ssize_t readline(int sockfd, void *buf, size_t maxline) {
	int ret;
	int nread;
	char *bufp = (char*)buf;
	int nleft = maxline;
	while (1) {
		ret = recv_peek(sockfd, bufp, nleft);
		if (ret < 0) {
			return ret;
		} else if (ret == 0) {
			return ret;
		}
		nread = ret;
		int i;
		for (i=0; i<nread; ++i) {
			if (bufp[i] == '\n') {
				ret = readn(sockfd, bufp, i+1);
				if (ret != i+1) {
					exit(EXIT_FAILURE);
				}
				return ret;
			}
		}
		if (nread > nleft) {
			exit(EXIT_FAILURE);
		}
		nleft -= nread;
		ret = readn(sockfd, bufp, nread);
		if (ret != nread) {
			exit(EXIT_FAILURE);
		}
		bufp += nread;
	}
	return -1;
}