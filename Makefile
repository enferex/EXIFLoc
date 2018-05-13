CC=clang
CFLAGS=-g3 -Wall -std=c11
APP=exifpluck

all: debug

$(APP): main.c
	$(CC) $(CFLAGS) $^ -o $@

.PHONY: release
release: CFLAGS += -DNDEBUG -O3
release: $(APP)

.PHONY: debug
debug: CFLAGS += -DDEBUG -O0
debug: $(APP)

clean:
	$(RM) $(APP)
