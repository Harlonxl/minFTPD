# minFTPD
minFTPD provide most of functions of FTP server. it's very simple, in order to learn the principle of FTP server.

# How to use minFTPD?
> make
> ./minftpd
0.0.0.0 listen address which minFTPD listens as defasult, 5188 ports as default.
You can use leapFTP in windows test minFTPD.
And you can use source Insight learn the source code.

# Code Tree
common.h --- common data structure
ftpcodes.h --- FTP status codes
ftpproto.c --- FTP command parse and operation
ftpproto.h --- ftpproto head file
main.c ---- setup minFTPD
Makefile --- Makefile file
miniftp.conf --- configuration file
parseconf.c --- parse configuration item
parseconf.h --- parseconf head file
parseconf_test.c --- parseconf test file
privparent.c --- nobody process command parse
privparent.h --- privparent head file
session.c --- session managent
session.h --- session head file
str.c --- base string function
str.h --- str head file
sysutil.c --- base common function
sysutil.h --- sysutil headfile
tunable.c --- configuration item definition
tunable.h --- tunable head file
