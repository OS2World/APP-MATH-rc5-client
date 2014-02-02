# rc5-56-client Makefile
#
OPTS_GCC=\
	-fcaller-saves -fcse-follow-jumps -fcse-skip-blocks \
	-fexpensive-optimizations -fomit-frame-pointer \
	-frerun-cse-after-loop -fstrength-reduce -fthread-jumps \
	-funroll-loops -O6 -Wall -s

SOCKS_OPTS = #-Lsocks5/lib -Isocks5/include -DSOCKS
SOCKS_LIBS = -lsocket

OPTS_CC_SPARC	= $(SOCKS_OPTS) -fast -xO4 -xtarget=ultra1/140 -DASM_SPARC
OPTS_GCC_SPARC	= $(OPTS_GCC) $(SOCKS_OPTS) -msupersparc -DASM_SPARC

OPTS_CC_MIPS	= $(SOCKS_OPTS) -O2 -xansi -OPT:fold_arith_limit=2000 -DASM_MIPS
OPTS_CC_MIPS	= -g -O2 -xansi
OPTS_GCC_MIPS	= $(OPTS_GCC) $(SOCKS_OPTS) -DASM_MIPS

OPTS_GCC_I486	= $(OPTS_GCC) $(SOCKS_OPTS) -m486 -DASM_I486 -Zexe -Zcrtdll

OPTS_CC_ALPHA	= -migrate -O5 -tune host -non_shared

COMMON_SRCS = common.c
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

CLIENT_SRCS = client.c cliops.c
CLIENT_OBJS = $(CLIENT_SRCS:.c=.o)

SERVER_SRCS = server.c servops.c keyspace.c
SERVER_OBJS = $(SERVER_SRCS:.c=.o)

PROXY_SRCS = proxy.c
PROXY_OBJS = $(PROXY_SRCS:.c=.o)

VERIFY_SRCS = verify.c
VERIFY_OBJS = $(VERIFY_SRCS:.c=.o)

PROGS = client #server proxy verify

all:; @echo nope

sparc-cc:
	$(MAKE) CC=cc CFLAGS="$(OPTS_CC_SPARC)" \
		LDFLAGS="$(OPTS_CC_SPARC)" \
		LIBS="-lnsl -lsocket $(SOCKS_LIBS)" \
		$(PROGS)

sparc-gcc:
	$(MAKE) CC=gcc CFLAGS="$(OPTS_GCC_SPARC)" \
		LDFLAGS="$(OPTS_GCC_SPARC)" \
		LIBS="-lnsl -lsocket $(SOCKS_LIBS)" \
		$(PROGS)

mips-cc:
	$(MAKE) CC=cc CFLAGS="$(OPTS_CC_MIPS)" \
		LDFLAGS="$(OPTS_CC_MIPS)" \
		LIBS="$(SOCKS_LIBS)" \
		$(PROGS)

mips-gcc:
	$(MAKE) CC=gcc CFLAGS="$(OPTS_GCC_MIPS)" \
		LDFLAGS="$(OPTS_GCC_MIPS)" \
		LIBS="$(SOCKS_LIBS)" \
		$(PROGS)

i486-gcc:
	$(MAKE) CC=gcc CFLAGS="$(OPTS_GCC_I486)" \
		LDFLAGS="$(OPTS_GCC_I486)" \
		LIBS="$(SOCKS_LIBS)" \
		$(PROGS)

alpha-cc:
	$(MAKE) CC=cc CFLAGS="$(OPTS_CC_ALPHA)" \
		LDFLAGS="$(OPTS_CC_ALPHA)" \
		LIBS="$(SOCKS_LIBS)" \
		$(PROGS)

client: $(CLIENT_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(CLIENT_OBJS) $(COMMON_OBJS) $(LIBS)

server: $(SERVER_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(COMMON_OBJS) $(LIBS)

proxy: $(PROXY_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(PROXY_OBJS) $(COMMON_OBJS) $(LIBS)

verify: $(VERIFY_OBJS) $(COMMON_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(VERIFY_OBJS) $(COMMON_OBJS) $(LIBS)

clean:
	$(RM) $(PROGS) $(COMMON_OBJS) $(CLIENT_OBJS) $(SERVER_OBJS) \
		$(PROXY_OBJS) $(VERIFY_OBJS)

