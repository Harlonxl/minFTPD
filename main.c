#include "common.h"
#include "session.h"
#include "sysutil.h"
#include "session.h"
#include "privparent.h"
#include "ftpproto.h"
#include "tunable.h"
#include "parseconf.h"
#include "ftpcodes.h"

extern session_t *p_sess;
static unsigned int s_children;

void check_limits(session_t *sess);
void handle_sigchld(int sig);

int main(int argc, char *argv[]) {
	// 加载配置项和配置文件
	parseconf_load_file(MINIFTP_CONF);
	daemon(0, 0);
	if (getuid() != 0) {
		fprintf(stderr, "%s: must be started as root\n", argv[0]);
	}

	session_t sess = {
		// 控制连接
		0, -1, "", "", "",
		// 数据连接
		NULL, -1, -1, 0,
		// 父子间通道
		-1, -1,
		// FTP协议状态
		0, 0, NULL, 0,
		0, 0, 0, 0,
		// 连接数限制
		0
	};

	p_sess = &sess;
	sess.bw_upload_rate_max = tunable_upload_max_rate;
	sess.bw_download_rate_max = tunable_download_max_rate;
	signal(SIGCHLD, handle_sigchld);
	int listenfd = tcp_server(tunable_listen_address, tunable_listen_port);
	int conn; 
	pid_t pid;

	while (1) {
		conn = accept_timeout(listenfd, NULL, 0);
		if (conn == -1) {
			ERR_EXIT("accept_timeout");
		}

		++s_children;
		sess.num_clients = s_children;

		pid = fork();
		if (pid == -1) {
			--s_children;
			ERR_EXIT("fork");
		}

		if (pid == 0) {
			close(listenfd);
			sess.ctrl_fd = conn;
			check_limits(&sess);
			signal(SIGCHLD, SIG_IGN);
			begin_session(&sess);
		} else {
			close(conn);
		}
	}

	return 0;
}

void check_limits(session_t *sess) {
	if (tunable_max_clients > 0 && sess->num_clients > tunable_max_clients) {
		ftp_replay(sess, FTP_TOO_MANY_USERS, "There too many connected users, please try later.");
		exit(EXIT_FAILURE);
	}
}

void handle_sigchld(int sig) {
	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0);
	--s_children;
}
