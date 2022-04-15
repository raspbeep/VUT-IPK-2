CC = gcc
CFLAGS = -std=c99 -Werror -Wall -Wextra -pedantic
EXEC = main
LIB = dynamic_string
TARGETS = Makefile errno.h hinfosvc.c Readme.md
PACK = xkrato61

all:
	$(CC) $(LIB).c $(EXEC).c -o $(EXEC) -lpcap -pedantic -Werror

pack:
	zip $(PACK) $(TARGETS)

clean:
	rm -rf $(EXEC) $(PACK).zip $(PACK)