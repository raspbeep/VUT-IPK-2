CC = gcc
CFLAGS = -std=c99 -Werror -Wall -Wextra -pedantic
EXEC = main
TARGETS = Makefile errno.h hinfosvc.c Readme.md
PACK = xkrato61

all:
	$(CC) $(EXEC).c -o $(EXEC) -lpcap -Wextra -pedantic -Werror

pack:
	zip $(PACK) $(TARGETS)

clean:
	rm -rf $(EXEC) $(PACK).zip $(PACK)