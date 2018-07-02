#include "common.h"
#include "session.h"
#include "sysutil.h"
#include "session.h"
#include "privparent.h"
#include "ftpproto.h"
#include "tunable.h"
#include "parseconf.h"

int main(int argc, char *argv[]) {
	// 加载配置项和配置文件
	parseconf_load_file(MINIFTP_CONF);

	if (getuid() != 0) {
		fprintf(stderr, "%s: must be started as root\n", argv[0]);
	}

	session_t sess = {
		// 控制连接
		0, -1, "", "", "",
		// 数据连接
		NULL, -1, -1,
		// 父子间通道
		-1, -1,
		// FTP协议状态
		0
	};
	signal(SIGCHLD, SIG_IGN);
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
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
