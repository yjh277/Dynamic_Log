###########################################
# Simple Makefile for ypub log module
#
# yjh277
# 2021-1-29
###########################################

all: libypub_log.so demo

CC = gcc
STRIP = strip
CFLAGS ?= -Werror -I. -L. -pipe -Os
LIBFLAGS ?= -lypub_log  -lpthread

# Console Test Program
libypub_log.so: ypub_log.c ypub_log.h
	$(CC) -fPIC -shared $(CFLAGS) $< -o $@
	$(STRIP) $@

demo:demo.c ypub_log.h
	$(CC) $(CFLAGS) $^ -o $@ $(LIBFLAGS)
	$(STRIP) $@	

clean:
	rm -f libypub_log.so demo
