include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = wtftp

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	packet-wtftp.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES = \
	packet-wtftp.h

HEADER_FILES = \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = wtftp.la

wtftp_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

wtftp_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

wtftp_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

wtftp_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	wtftp \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in	\
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	CMakeLists.txt
