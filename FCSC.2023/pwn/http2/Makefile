CFLAGS  += -fstack-protector-strong -ggdb -pthread
LDFLAGS += -z now -z relro

.PHONY: all
all: main getflag2

main: main.c http.c

.PHONY: clean
clean:
	rm -f main getflag2
