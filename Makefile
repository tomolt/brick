CC=gcc
LD=gcc
CFLAGS=-g -Wall -Wextra -pedantic
LDFLAGS=-g

.PHONY: all clean

all: brick bricks grantsocket

clean:
	rm -f brick.o  brick
	rm -f bricks.o bricks
	rm -f grantsocket.o grantsocket

brick: brick.o
	$(LD) $(LDFLAGS) $^ -o $@

brick.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@

bricks: bricks.o
	$(LD) $(LDFLAGS) $^ -o $@ -ltls

bricks.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@ -DBRICK_TLS=1

grantsocket: grantsocket.o
	$(LD) $(LDFLAGS) $^ -o $@

grantsocket.o: grantsocket.c
	$(CC) $(CFLAGS) -c $^ -o $@
