CC = gcc
CFLAGS = -std=c99 -Werror -Wall -Wextra -pedantic
EXEC = ipk-sniffer
LIB = dynamic_string
TARGETS = Makefile Readme.md $(EXEC).c $(LIB).h $(LIB).c errno.h
PACK = xkrato61

all:
	$(CC) $(LIB).c $(EXEC).c -o $(EXEC) -lpcap -pedantic -Werror -Wall

pack: clean
	zip $(PACK) $(TARGETS)

clean:
	rm -rf $(EXEC) $(PACK).zip $(PACK)