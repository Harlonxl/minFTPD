# minFTPD
minFTPD provide most of functions of FTP server. it's very simple, in order to learn the principle of FTP server.

# How to use minFTPD?
> make<br/>
> ./minftpd

0.0.0.0 listen address which minFTPD listens as defasult, 5188 ports as default.<br/>
You can use leapFTP in windows test minFTPD.<br/>
And you can use source Insight learn the source code.<br/>

# Code Tree
``` c++
minFTPD
│--- common.h 				common data structure
│--- ftpcodes.h  			FTP status codes
│--- ftpproto.c 			FTP command parse and operation
│--- ftpproto.h 			ftpproto head file
│--- ftpproto_test.c 			ftprpoto test file
│--- hash.c 				hash function
│--- hash.h 				hash head file
│--- hash_test.c  			hash test file
│--- main.c 				setup minFTPD
│--- Makefile 				Makefile file
│--- miniftp.conf 			configuration file
│--- parseconf.c  			parse configuration item
│--- parseconf.h  			parseconf head file
│--- parseconf_test.c 			parseconf test file
│--- privparent.c 			nobody process command parse
│--- privparent.h 			privparent head file
│--- privsock.c 			interprocess communication function 
│--- privsock.h 			privsock head file
│--- session.c 				session managentment
│--- session.h 				session head file
│--- str.c 				base string function
│--- str.h 				str head file
│--- sysutil.c  			base common function, include network、file operation
│--- sysutil.h 				sysutil headfile
│--- tunable.c 				configuration item definition
|--- tunable.h  			tunable head file
```

