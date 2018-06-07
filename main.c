#include "common.h"
#include "session.h"
#include "sysutil.h"
#include "session.h"
#include "privparent.h"
#include "ftpproto.h"

int main(int argc, char *argv[]) {
	if (getuid() != 0) {
		fprintf(stderr, "%s: must be started as root\n", argv[0]);
	}

	session_t sess = {
		// 控制连接
		-1, "", "", "", 
		// 父子间通道
		-1, -1
	};
	int listenfd = tcp_server(NULL, 5188);
	int conn;
	pid_t pid;

	while (1) {
		conn = accept_timeout(listenfd, NULL, 0);
		if (conn == -1) {
			ERR_EXIT("accept_timeout");
		}

		pid = fork();
		if (pid == -1) {
			ERR_EXIT("fork");
		}

		if (pid == 0) {
			close(listenfd);
			sess.ctrl_fd = conn;
			begin_session(&sess);
		} else {
			close(listenfd);
		}
	}

	return 0;
}