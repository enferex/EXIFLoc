CC=clang
CFLAGS=-g3 -Wall -std=c11
APP=exifloc

all: release

$(APP): main.c
	$(CC) $(CFLAGS) $^ -o $@ -lm

.PHONY: test
test: $(APP)
	./$(APP) ./test.jpg

.PHONY: release
release: CFLAGS += -DNDEBUG -O3
release: $(APP)

.PHONY: debug
debug: CFLAGS += -DDEBUG -O0
debug: $(APP)

clean:
	$(RM) $(APP)
