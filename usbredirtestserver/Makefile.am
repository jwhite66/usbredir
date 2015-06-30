noinst_PROGRAMS = usbredirtestserver

usbredirtestserver_SOURCES = usbredirtestserver.c
usbredirtestserver_LDADD = $(top_builddir)/usbredirparser/libusbredirparser.la $(READLINE_LIBS) $(PTHREAD_LIBS)
usbredirtestserver_CFLAGS = -I$(top_srcdir)/usbredirparser

-include $(top_srcdir)/git.mk
