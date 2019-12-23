PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
INCLUDEDIR ?= $(PREFIX)/include
LIBDIR ?= $(PREFIX)/lib

PKG_CONFIG ?= pkg-config
LIB_CFLAGS   = $(CFLAGS)
LIB_LDFLAGS  ?= $(LDFLAGS)
LIB_CFLAGS  += -Wall -Wextra -g -fstack-protector-all -Ilib -fPIC
LIB_CFLAGS  += -Iinclude $(shell $(PKG_CONFIG) --cflags libnl-3.0 libnl-genl-3.0) $(shell $(PKG_CONFIG) --cflags libcjson) -Imain
#LIB_LDFLAGS += -lnl-3

BIN_CFLAGS   = $(CFLAGS)
BIN_LDFLAGS  = $(LDFLAGS)
BIN_CFLAGS  += -Wall -Wextra -Wno-error=unused-parameter -Wno-error=sign-compare -Wno-format-security -g -fstack-protector-all -Imain
BIN_CFLAGS  += $(shell $(PKG_CONFIG) --cflags libnl-3.0 libnl-genl-3.0 libcjson) -Iinclude
BIN_LDFLAGS += -ltsn $(shell $(PKG_CONFIG) --libs libnl-3.0 libnl-genl-3.0 libcjson) -lpthread -lm -lrt
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
TSN_LIB_PC = libtsn.pc
TSN_EVENT = event
TSTAMP_BIN = timestamping

LIB_VERSION = 0

build: $(TSN_LIB) $(TSN_BIN)

tools: $(TSN_EVENT) $(TSTAMP_BIN)

$(TSN_LIB): $(LIB_DEPS)
	$(CC) -shared $(LIB_OBJ) -o $@ $(LIB_LDFLAGS)

$(TSN_BIN): $(BIN_DEPS) $(TSN_LIB)
	$(CC) $(BIN_OBJ) -o $@ $(BIN_LDFLAGS)

$(TSN_EVENT): tools/$(TSN_EVENT).o $(TSN_LIB)
	$(CC) tools/$(TSN_EVENT).o -o tools/$(TSN_EVENT) $(BIN_LDFLAGS)

$(TSTAMP_BIN): tools/$(TSTAMP_BIN).o
	$(CC) tools/$(TSTAMP_BIN).o -o tools/$(TSTAMP_BIN) -lpthread -lm

lib/%.o: lib/%.c
	$(CC)  -c $^ -o $@ $(LIB_CFLAGS)

main/%.o: main/%.c
	$(CC)  -c $^ -o $@ $(BIN_CFLAGS)

tools/$(TSN_EVENT).o: tools/$(TSN_EVENT).c
	$(CC) -c tools/$(TSN_EVENT).c -o tools/$(TSN_EVENT).o $(BIN_CFLAGS)

tools/$(TSTAMP_BIN).o: tools/$(TSTAMP_BIN).c
	$(CC) -c tools/$(TSTAMP_BIN).c -o tools/$(TSTAMP_BIN).o $(BIN_CFLAGS)

$(TSN_LIB_PC): lib/libtsn.pc.in
	sed -e "s#@includedir@#$(INCLUDEDIR)#g" \
		-e "s#@libdir@#$(LIBDIR)#g" \
		-e "s#@version@#$(LIB_VERSION)#g" \
		$< > $@

install: include/tsn/genl_tsn.h $(TSN_LIB) $(TSN_BIN) $(TSN_LIB_PC)
	install -d -m 0755 $(DESTDIR)$(BINDIR)
	install -d -m 0755 $(DESTDIR)$(LIBDIR)
	install -d -m 0755 $(DESTDIR)$(INCLUDEDIR)/tsn
	install -m 0755 $(TSN_BIN) $(DESTDIR)$(BINDIR)/
	install -m 0644 $(TSN_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 0644 include/tsn/genl_tsn.h $(DESTDIR)$(INCLUDEDIR)/tsn
	install -D -m 644 $(TSN_LIB_PC) $(DESTDIR)$(LIBDIR)/pkgconfig/libtsn.pc

clean:
	rm -rf $(TSN_BIN) $(TSN_LIB) $(TSN_LIB_PC) $(LIB_OBJ) $(BIN_OBJ) tools/*.o tools/$(TSN_EVENT) tools/$(TSTAMP_BIN)

.PHONY: clean build
