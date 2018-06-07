#include "common.h"
#include "session.h"

void begin_session(session_t *sess) {
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL) {
		return;
	}
	if (setegid(pw->pw_gid) < 0) {
		ERR_EXIT("setegid");
	}
	if (seteuid(pw->pw_uid) < 0) {
		ERR_EXIT("seteuid");
	}
	int sockfds[2];
	if (socketpair(PF_UNIX, SOCK_STREAM, 0, sockfds) < 0) {
		ERR_EXIT("sockpair");
	}

	pid_t pid;
	pid = fork();
	if (pid < 0) {
		ERR_EXIT("fork");
	}

	if (pid == 0) {
		// ftp服务进程
		close(sockfds[0]);
		sess->child_fd = sockfds[1];
		handle_child(sess);
	} else {
		// nobody进程
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		handle_parent(sess);
	}
}