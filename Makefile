CC = clang
STRIP = strip
OBJS = pseudo_node.o
CFLAGS = -std=gnu99 -DLINUX -O2 -Wall -Wno-unused-value -fpic
CLIBS = -lpthread -ldl -Wl,-R.

pseudonode: libpseudonode.so main.o
	$(CC) $(CFLAGS) -o pseudonode main.o $(CLIBS) -L. libpseudonode.so
	$(STRIP) pseudonode
	cp pseudonode pseudonode.linux

libpseudonode.so: $(OBJS)
	$(CC) -shared -o libpseudonode.so $(OBJS)

clean:
	rm -f $(OBJS) main.o libpseudonode.so pseduonode

