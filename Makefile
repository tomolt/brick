NAME=brick
VERSION=0.1
PREFIX=/usr/local
MANPREFIX=$(PREFIX)/share/doc

CC=gcc
LD=gcc
CFLAGS=-g -Wall -Wextra -pedantic
LDFLAGS=-g

SRC=brick.c grantsocket.c
HDR=arg.h
OBJ=$(SRC:.c=.o)
BIN=brick bricks grantsocket
MAN1=brick.1 grantsocket.1

.PHONY: all clean dist install uninstall

all: $(BIN)

clean:
	rm -f $(OBJ) $(BIN)

dist:
	rm -rf .dist
	mkdir -p .dist
	cp -f $(SRC) $(HDR) $(MAN1) Makefile README.md
	tar -cf - .dist | gzip -c > $(NAME)-$(VERSION).tar.gz
	rm -rf .dist

install: all
	# install executables
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f $(BIN) $(DESTDIR)$(PREFIX)/bin
	for f in $(BIN); do chmod 755 $(DESTDIR)$(PREFIX)/bin/$$f; done
	# install manual pages
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	cp -f $(MAN1) $(DESTDIR)$(MANPREFIX)/man1
	for f in $(MAN1); do chmod 644 $(DESTDIR)$(MANPREFIX)/man1/$$f; done

uninstall:
	# remove executables
	for f in $(BIN); do rm -f $(DESTDIR)$(PREFIX)/bin/$$f; done
	# remove manual pages
	for f in $(MAN1); do rm -f $(DESTDIR)$(MANPREFIX)/man1/$$f; done

brick: brick.o
	$(LD) $(LDFLAGS) $^ -o $@

brick.o: brick.c
	$(CC) $(CFLAGS) -c $^ -o $@

bricks: bricks.o
	$(LD) $(LDFLAGS) $^ -o $@ -ltls

bricks.o: brick.c
	$(CC) $(CFLAGS) -c $< -o $@ -DBRICK_TLS=1

grantsocket: grantsocket.o
	$(LD) $(LDFLAGS) $^ -o $@

grantsocket.o: grantsocket.c arg.h
	$(CC) $(CFLAGS) -c $< -o $@

