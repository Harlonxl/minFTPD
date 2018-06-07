#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_EXIT(m)	\
	do 	\
	{ 	\
		perror(m); 	\
		exit(EXIT_FAILURE); 	\
	} while (0); 	\


#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 1024
#define MAX_ARG 1024

#endif /*_COMMON_H_*/