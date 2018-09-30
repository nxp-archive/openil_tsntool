BINNAME = tsntool
CFLAGS =
SOURCES = fill.c cmd.c readinput.c main.c
readlink = readlink
srcdir = .


LIBS = -lxml2 -lreadline
ifeq "$(shell pwd)" "$(shell $(readlink) -f $(srcdir))"
OBJDIR= .obj
else
OBJDIR= .
endif
CC = gcc
CLFAGS += -g -O2


LIBNL_CFLAGS = -I/usr/include/libnl3 -I$(shell pwd)/../include/
LIBNL_LIBS = -lnl-3

AM_CFLAGS = -Wall -Wextra -Wformat=2 $(LIBCONFIG_CFLAGS) $(LIBNL_CFLAGS)
AM_LDFLAGS = $(LIBCONFIG_LIBS) $(LIBNL_LIBS) -lrt

CFLAGS += $(AM_CFLAGS)
LIBS += $(AM_LDFLAGS)


INCLUDES = readinput.h main.h

OBJS = $(SOURCES:%.c=$(OBJDIR)/%.o)

all: $(BINNAME)
$(BINNAME) : $(OBJS)
	 $(CC) $(CFLAGS) $(OBJS) $(LIBS) -o $(BINNAME)

$(OBJDIR)/%.o: %.c
	@[ -d $$(dirname $@) ] || \
		(mkdir -p $$(dirname $@))
	$(CC) $(CFLAGS) -c $^ -o $@

.PHONY:clean
clean:
	rm -rf *.o; rm -rf $(BINNAME); rm -rf .obj/
