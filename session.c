#include "common.h"
#include "session.h"
#include "ftpproto.h"
#include "privparent.h"
#include "privsock.h"

void begin_session(session_t *sess) {
	priv_sock_init(sess);
	pid_t pid;
	pid = fork();
	if (pid < 0) {
		ERR_EXIT("fork");
	}

	if (pid == 0) {
		// ftp服务进程
		priv_sock_set_child_context(sess);
		handle_child(sess);
	} else {
		// nobody进程
		priv_sock_set_parent_context(sess);
		handle_parent(sess);
	}
}