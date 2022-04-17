CC=gcc
LD=gcc
CFLAGS=-Os -Wall -Wextra -pedantic
LDFLAGS=-Os

.PHONY: all clean

all: brick

clean:
	rm -f *.o
	rm -f brick

brick: brick.o
	$(LD) $(LDFLAGS) $^ -o $@

brick.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@

