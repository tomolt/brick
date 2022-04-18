CC=gcc
LD=gcc
CFLAGS=-g -Wall -Wextra -pedantic
LDFLAGS=-g

.PHONY: all clean

all: brick bricks

clean:
	rm -f brick.o  brick
	rm -f bricks.o bricks

brick: brick.o
	$(LD) $(LDFLAGS) $^ -o $@

brick.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@

bricks: bricks.o
	$(LD) $(LDFLAGS) $^ -o $@ -ltls

bricks.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@ -DBRICK_TLS=1

