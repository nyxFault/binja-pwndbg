CC ?= gcc
CFLAGS_COMMON := -fno-omit-frame-pointer

SRC := crackme.c
BIN_STRIPPED := crackme
BIN_DEBUG := crackme_dbg

.PHONY: all stripped debug clean

all: stripped

stripped: $(SRC)
	$(CC) -O2 -s $(CFLAGS_COMMON) -o $(BIN_STRIPPED) $(SRC)

debug: $(SRC)
	$(CC) -O0 -g $(CFLAGS_COMMON) -o $(BIN_DEBUG) $(SRC)

clean:
	rm -f $(BIN_STRIPPED) $(BIN_DEBUG)
