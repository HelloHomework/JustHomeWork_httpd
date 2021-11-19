SHELL = /bin/bash
CC = gcc
CFLAGS= -O3
DEBUG_FLAGS = -g -W -Wall -D DEBUG
SRC = $(wildcard *.c)
EXE = $(patsubst %.c, %, $(SRC))

all: httpd.c
	${CC} ${CFLAGS} httpd.c -o httpd

debug: httpd.c
	${CC} ${DEBUG_FLAGS} httpd.c -o httpd

clean:
	rm ${EXE}

