#include "ftpproto.h"

void handle_child(session_t *sess) {
	writen(sess->ctrl_fd, "220 (minftpd 0.1)\r\n", strlen("220 (minftpd 0.1)\r\n"));

	while (1) {
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);

		// 解析FTP命令与参数
		// 处理FTP命令

	}
}