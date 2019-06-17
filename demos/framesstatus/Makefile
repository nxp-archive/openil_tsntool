LIB_CFLAGS   = $(CFLAGS)
LIB_LDFLAGS  ?= $(LDFLAGS)
LIB_CFLAGS  += -Wall -Wextra -g -fstack-protector-all -Ilib -fPIC
LIB_CFLAGS  += -Iinclude $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0) $(shell pkg-config --cflags libcjson)
#LIB_LDFLAGS += -lnl-3

BIN_CFLAGS   = $(CFLAGS)
BIN_LDFLAGS  = $(LDFLAGS)
BIN_CFLAGS  += -Wall -Wextra -Wno-error=unused-parameter -Wno-error=sign-compare -g -fstack-protector-all
BIN_CFLAGS  += $(shell pkg-config --cflags libnl-3.0 libnl-genl-3.0 libcjson) -I../../include
BIN_LDFLAGS += -L../../ -ltsn $(shell pkg-config --libs libnl-3.0 libnl-genl-3.0 libcjson) -lpthread -lm -lrt
BIN_LDFLAGS += -lreadline -ltermcap -L.
BIN_LDFLAGS += -Wl,-rpath,$(shell pwd)         # Compiled lib at local folder

FRAMECAP = enetctscap
#CYCLECAP = cyclecap

build: $(FRAMECAP) $(CYCLECAP)

$(FRAMECAP): $(FRAMECAP).o
	$(CC) $(FRAMECAP).o -o webserver/$(FRAMECAP) $(BIN_LDFLAGS)

#$(CYCLECAP): $(CYCLECAP).o
#	$(CC) $(CYCLECAP).o -o $(CYCLECAP) $(BIN_LDFLAGS)

$(FRAMECAP).o: $(FRAMECAP).c
	$(CC) -c $(FRAMECAP).c -o $(FRAMECAP).o $(BIN_CFLAGS)

#$(CYCLECAP).o: $(CYCLECAP).c
#	$(CC) -c $(CYCLECAP).c -o $(CYCLECAP).o $(BIN_CFLAGS)

clean:
	rm -rf *.o webserver/$(FRAMECAP) $(CYCLECAP)

.PHONY: clean build
