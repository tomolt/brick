CC=gcc
LD=gcc
CFLAGS=-Os -Wall -Wextra -pedantic
LDFLAGS=-Os
LIBS=-ltls

.PHONY: all clean

all: brick

clean:
	rm -f *.o
	rm -f brick

brick: brick.o
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBS)

brick.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@

