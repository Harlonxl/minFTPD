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
sheepdog
│···
└─── dog
      │farm
      │benchmark.c Dog的benchmark
      │cluster.c Sheepdog集群命令处理文件
      │common.c 通用函数模块
      │dog.c 程序初始化和入口文件
      │nfs.c NFS文件系统相关命令
      │node.c 节点命令处理文件
      │trace.c 跟踪及调试文件
      │treeview.c 查看跟踪及调试文件
      │upgrade.c 更新操作
      │vdi.c 块设备命令处理文件
      │dog.h dog操作头文件
      │treeview.h vid树头文件
│···
```
> common.h              common data structure<br/>
> ftpcodes.h 		FTP status codes<br/>
> ftpproto.c  		FTP command parse and operation<br/>
> ftpproto.h --- ftpproto head file<br/>
> main.c ---- setup minFTPD<br/>
> Makefile --- Makefile file<br/>
> miniftp.conf --- configuration file<br/>
> parseconf.c --- parse configuration item<br/>
> parseconf.h --- parseconf head file<br/>
> parseconf_test.c --- parseconf test file<br/>
> privparent.c --- nobody process command parse<br/>
> privparent.h --- privparent head file<br/>
> session.c --- session managent<br/>
> session.h --- session head file<br/>
> str.c --- base string function<br/>
> str.h --- str head file<br/>
> sysutil.c --- base common function<br/>
> sysutil.h --- sysutil headfile<br/>
> tunable.c --- configuration item definition<br/>
> tunable.h --- tunable head file<br/>
