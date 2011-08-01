PIDGINDIR = /opt/local/pidgin-2.7.1
INCLUDE = -I$(PIDGINDIR)/include/libpurple $(shell python-config --include) \
					$(shell pkg-config --cflags glib-2.0)
CFLAGS  = -g -c -fPIC $(INCLUDE)
LDFLAGS = -L$(PIDGINDIR)/lib $(shell python-config --ldflags) \
					$(shell pkg-config --libs glib-2.0) -shared -dynamiclib

SOURCES = $(wildcard *.i)
TARGETS = $(SOURCES:%.i=_%.so)

all: $(TARGETS)

clean:
	  $(RM) $(SOURCES:i=py) *_wrap.c *.o *.pyc *.so

_purple.so: purple_wrap.o purple.o
	  $(CC) -o $@ $^ -lglib-2.0 -lgobject-2.0 -lgthread-2.0 -lpython2.6 \
			-lpurple -lz $(LDFLAGS)

.c.o:
	  $(CC) $(CFLAGS) -o $@ $<

%_wrap.c %.py: %.i
	  swig -python $(INCLUDE) $<
