AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-oqs.la
else
plugin_LTLIBRARIES = libstrongswan-oqs.la
endif

libstrongswan_oqs_la_SOURCES = \
	oqs_plugin.h oqs_plugin.c \
	oqs_qske.h oqs_qske.c

libstrongswan_oqs_la_LDFLAGS = -module -avoid-version
libstrongswan_oqs_la_LIBADD  = -loqs
