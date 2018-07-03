#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/capability.h>
#include <sys/syscall.h>
#include <sys/sendfile.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ERR_EXIT(m)	\
	do 	\
	{ 	\
		perror(m); 	\
		exit(EXIT_FAILURE); 	\
	} while (0); 	\


#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 1024
#define MAX_ARG 1024
#define MINIFTP_CONF "miniftp.conf"

#endif /*_COMMON_H_*/