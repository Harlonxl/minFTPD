#include "privsock.h"
#include "session.h"
#include "sysutil.h"

void priv_sock_init(session_t *sess) {
	int sockfds[2];
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0) {
		ERR_EXIT("sockpair");
	}
	sess->parent_fd = sockfds[0];
	sess->child_fd = sockfds[1];
}

void priv_sock_close(session_t *sess) {
	if (sess->child_fd != -1) {
		close(sess->child_fd);
		sess->child_fd = -1;
	}
	if (sess->parent_fd != -1) {
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
}
void priv_sock_set_parent_context(session_t *sess) {
	if (sess->child_fd != -1) {
		close(sess->child_fd);
		sess->child_fd = -1;
	}
}
void priv_sock_set_child_context(session_t *sess) {
	if (sess->parent_fd != -1) {
		close(sess->parent_fd);
		sess->parent_fd = -1;
	}
}

void priv_sock_send_cmd(int fd, char cmd) {
	int ret;
	ret = writen(fd, &cmd, sizeof(cmd));

	if (ret != sizeof(cmd)) {
		ERR_EXIT("priv_sock_send_cmd");
	}
}

char priv_sock_get_cmd(int fd) {
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res)) {
		ERR_EXIT("priv_sock_get_cmd");
	}
	return res;
}

void priv_sock_send_result(int fd, char res) {
	int ret;
	ret = writen(fd, &res, sizeof(res));

	if (ret != sizeof(res)) {
		ERR_EXIT("priv_sock_send_result");
	}
}

char priv_sock_get_result(int fd) {
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res)) {
		ERR_EXIT("priv_sock_get_result");
	}
	return res;
}

void priv_sock_send_int(int fd, int the_int) {
	int ret;
	ret = writen(fd, &the_int, sizeof(the_int));

	if (ret != sizeof(the_int)) {
		ERR_EXIT("priv_sock_send_int");
	}
}

int priv_sock_get_int(int fd) {
	int res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res)) {
		ERR_EXIT("priv_sock_get_int");
	}
	return res;
}

void priv_sock_send_buf(int fd, const char *buf, unsigned int len) {
	priv_sock_send_int(fd, (int)len);
	int ret = writen(fd, buf, len);
	if (ret != (int)len) {
		ERR_EXIT("priv_sock_send_buf");
	}
}

void priv_sock_recv_buf(int fd, char *buf, unsigned int len) {
	unsigned int recvlen = (unsigned int)priv_sock_get_int(fd);
	if (recvlen > len) {
		ERR_EXIT("priv_sock_recv_buf");
	}
	int ret = readn(fd, buf, recvlen);
	if (ret != (int)recvlen) {
		ERR_EXIT("priv_sock_send_buf");
	}
}

void priv_sock_send_fd(int sockfd, int fd) {
	send_fd(sockfd, fd);
}

int priv_sock_recv_fd(int sockfd) {
	return recv_fd(sockfd);
}

