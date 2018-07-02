CC=gcc
CFLAGS=-Wall -g
BIN=minftpd
OBJS=main.o sysutil.o session.o ftpproto.o privparent.o str.o tunable.o parseconf.o privsock.o
LIBS=-lcrypt
$(BIN):$(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LIBS)
%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@
clean:
	rm -f *.o $(BIN) 