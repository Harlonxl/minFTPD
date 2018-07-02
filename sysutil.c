#include "sysutil.h"


int tcp_client(unsigned short port) {
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		ERR_EXIT("tcp_client");
	}

	if (port > 0) {
		int on = 1;
		if ((setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on))) < 0) {
			ERR_EXIT("setsockopt");
		}
		char ip[16] = {0};
		getlocalip(ip);
		struct sockaddr_in localaddr;
		memset(&localaddr, 0, sizeof(localaddr));
		localaddr.sin_family = AF_INET;
		localaddr.sin_port = htons(port);
		localaddr.sin_addr.s_addr = inet_addr(ip);
		if (bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr)) < 0) {
			ERR_EXIT("bind");
		}
	}

	return sock;

}

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
ssize_t writen(int fd, const void *buf, size_t n) {
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

int getlocalip(char *ip)
{
	char host[100] = {0};
	if (gethostname(host, sizeof(host)) < 0)
		return -1;
	struct hostent *hp;
	if ((hp = gethostbyname(host)) == NULL)
	return -1;

	strcpy(ip, inet_ntoa(*(struct in_addr*)hp->h_addr));
	return 0;
}

/**
 * activate_noblock - 设置I/O为非阻塞模式
 * @fd: 文件描符符
 */
void activate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");
	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}
/**
 * deactivate_nonblock - 设置I/O为阻塞模式
 * @fd: 文件描符符
 */
void deactivate_nonblock(int fd)
{
	int ret;
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		ERR_EXIT("fcntl");
	flags &= ~O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	if (ret == -1)
		ERR_EXIT("fcntl");
}
/**
 * connect_timeout - connect
 * @fd: 套接字
 * @addr: 要连接的对方地址
 * @wait_seconds: 等待超时秒数，如果为0表示正常模式
 * 成功（未超时）返回0，失败返回-1，超时返回-1并且errno = ETIMEDOUT
 */
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds) {
	int ret;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	if (wait_seconds > 0) {
		activate_nonblock(fd);
	}
	ret = connect(fd, (struct sockaddr*)addr, addrlen);
	if (ret < 0 && errno == EINPROGRESS) {
		fd_set connect_fdset;
		struct timeval timeout;
		FD_ZERO(&connect_fdset);
		FD_SET(fd, &connect_fdset);
		timeout.tv_sec = wait_seconds;
		timeout.tv_usec = 0;
		do {
			/* 一量连接建立，套接字就可写 */
			ret = select(fd + 1, NULL, &connect_fdset, NULL, &timeout);
		} while (ret < 0 && errno == EINTR);
		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		} else if (ret < 0) {
			return -1;
		} else if (ret == 1) {
			/* ret返回为1，可能有两种情况，一种是连接建立成功，一种是套接字产生错误，*/
			/* 此时错误信息不会保存至errno变量中，因此，需要调用getsockopt来获取。 */
			int err;
			socklen_t socklen = sizeof(err);
			int sockoptret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &socklen);
			if (sockoptret == -1) {
				return -1;
			}
			if (err == 0) {
				ret = 0;
			} else {
				errno = err;
				ret = -1;
			}
		}
	}
	if (wait_seconds > 0) {
		deactivate_nonblock(fd);
	}
	return ret;
}

void send_fd(int sock_fd, int fd) {
	int ret;
	struct msghdr msg;
	struct cmsghdr *p_cmsg;
	struct iovec vec;
	char cmsgbuf[CMSG_SPACE(sizeof(fd))];
	int *p_fds;
	char sendchar = 0;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

int recv_fd(const int sock_fd) {
	int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}

const char *statbuf_get_perms(struct stat *sbuf) {
	static char perms[] = "----------";
	perms[0] = '?';

	mode_t mode = sbuf->st_mode;
	switch (mode & S_IFMT) {
	case S_IFREG:
		perms[0] = '-';
		break;
	case S_IFDIR:
		perms[0] = 'd';
		break;
	case S_IFLNK:
		perms[0] = 'l';
		break;
	case S_IFIFO:
		perms[0] = 'p';
		break;
	case S_IFSOCK:
		perms[0] = 's';
		break;
	case S_IFCHR:
		perms[0] = 'c';
		break;
	case S_IFBLK:
		perms[0] = 'b';
		break;
	}

	if (mode & S_IRUSR) {
		perms[1] = 'r';
	}
	if (mode & S_IWUSR) {
		perms[2] = 'w';
	}
	if (mode & S_IXUSR) {
		perms[3] = 'x';
	}

	if (mode & S_IRGRP) {
		perms[4] = 'r';
	}
	if (mode & S_IWGRP) {
		perms[5] = 'w';
	}
	if (mode & S_IXGRP) {
		perms[6] = 'x';
	}

	if (mode & S_IROTH) {
		perms[7] = 'r';
	}
	if (mode & S_IWOTH) {
		perms[8] = 'w';
	}
	if (mode & S_IXOTH) {
		perms[9] = 'x';
	}

	if (mode & S_ISUID) {
		perms[3] = (perms[3] == 'x') ? 's' : 'S';
	}

	if (mode & S_ISGID) {
		perms[6] = (perms[6] == 'x') ? 's' : 'S';
	}

	if (mode & S_ISVTX) {
		perms[9] = (perms[9] == 'x') ? 't' : 'T';
	}
	return perms;
}

const char *statbuf_get_date(struct stat *sbuf) {
	static char datebuf[64] = {0};
	const char *p_data_format = "%b %e %H:%M";
	struct timeval tv;
	gettimeofday(&tv, NULL);
	long local_time = tv.tv_sec;
	if (sbuf->st_mtime > local_time || (local_time - sbuf->st_mtime) > 60 * 60 * 24 * 182) {
		p_data_format = "%b %e %Y";
	}

	struct tm *p_tm = localtime(&local_time);
	strftime(datebuf, sizeof(datebuf), p_data_format, p_tm);
	return datebuf;
}