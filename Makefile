CC = clang
STRIP = strip
OBJS = pseudo_node.o sha256.o
CFLAGS = -std=gnu99 -DLINUX -O2 -Wall -Wno-unused-value
CLIBS = -lpthread -ldl

pseudonode: $(OBJS)
	$(CC) $(CFLAGS) -o pseudonode $(OBJS) $(CLIBS)
	$(STRIP) pseudonode
	cp pseudonode pseudonode.linux

clean:
	rm -f $(OBJS) pseduonode

