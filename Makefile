LIB_CFLAGS   = $(CFLAGS)
LIB_LDFLAGS  ?= $(LDFLAGS)
LIB_CFLAGS  += -Wall -Wextra -g -fstack-protector-all -Ilib -fPIC
LIB_CFLAGS  += -Iinclude $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0) $(shell pkg-config --cflags libcjson) -Imain
#LIB_LDFLAGS += -lnl-3

BIN_CFLAGS   = $(CFLAGS)
BIN_LDFLAGS  = $(LDFLAGS)
BIN_CFLAGS  += -Wall -Wextra -Wno-error=unused-parameter -Wno-error=sign-compare -g -fstack-protector-all -Imain
BIN_CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0) -Iinclude
BIN_LDFLAGS += -ltsn $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0 libcjson) -lpthread -lm -lrt
BIN_LDFLAGS += -lreadline -ltermcap -L.
BIN_LDFLAGS += -Wl,-rpath,$(shell pwd)         # Compiled lib at local folder

BIN_SRC =
LIB_SRC =
BIN_SRC += $(shell find main -name "*.[c|h]")  # All .c and .h file
BIN_DEPS = $(patsubst %.c, %.o, $(BIN_SRC))        # All .o and .h files
BIN_OBJ  = $(filter %.o, $(BIN_DEPS))              # Only the .o files

LIB_SRC += $(shell find lib -name "*.[c|h]")   # All .c and .h files
LIB_DEPS = $(patsubst %.c, %.o, $(LIB_SRC))        # All .o and .h files
LIB_OBJ  = $(filter %.o, $(LIB_DEPS))              # Only the .o files

TSN_BIN = tsntool
TSN_LIB = libtsn.so
TSN_EVENT = event

build: $(TSN_LIB) $(TSN_BIN) $(TSN_EVENT)

$(TSN_LIB): $(LIB_DEPS)
	$(CC) -shared $(LIB_OBJ) -o $@ $(LIB_LDFLAGS)

$(TSN_BIN): $(BIN_DEPS)
	$(CC) $(BIN_OBJ) -o $@ $(BIN_LDFLAGS)

$(TSN_EVENT): tools/event.o
	$(CC) tools/event.o -o tools/$(TSN_EVENT) $(BIN_LDFLAGS)

lib/%.o: lib/%.c
	$(CC)  -c $^ -o $@ $(LIB_CFLAGS)

main/%.o: main/%.c
	$(CC)  -c $^ -o $@ $(BIN_CFLAGS)

tools/event.o: tools/event.c
	$(CC) -c tools/event.c -o tools/event.o $(BIN_CFLAGS)

clean:
	rm -rf $(TSN_BIN) $(TSN_LIB) $(LIB_OBJ) $(BIN_OBJ) tools/event.o tools/event

.PHONY: clean build
