## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for YAF
## ------------------------------------------------------------------------
## Copyright (C) 2006-2018 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Emily Sarneso
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

PODFILES = getFlowKeyHash.pod yafMeta2Pcap.pod ipfixDump.pod yafzcbalance.pod
man1_MANS = getFlowKeyHash.1 yafMeta2Pcap.1 ipfixDump.1 yafzcbalance.1 
HTMLFILES = getFlowKeyHash.html yafMeta2Pcap.html ipfixDump.html yafzcbalance.html

bin_PROGRAMS = getFlowKeyHash yafMeta2Pcap ipfixDump

if HASPFRINGZC
bin_PROGRAMS += yafzcbalance
endif

.pod.1:
	$(POD2MAN) $(YAF_POD2MAN_ARGS) --section=1 $< $@

.pod.html:
	$(POD2HTML) --noindex --infile="$<" --outfile="$@"
	$(top_srcdir)/doc/add-header.pl "$@"

copy-man-pages: $(HTMLFILES)
	mkdir -p $(top_builddir)/doc/html
	cp $(HTMLFILES) $(top_builddir)/doc/html

docs: $(man1_MANS) copy-man-pages

clean-docs:
	rm -f $(man1_MANS) $(HTMLFILES)

CLEANFILES = $(man1_MANS) $(HTMLFILES)

EXTRA_DIST = $(PODFILES) \
	yafzcbalance.c

clean-local:
	rm -f pod2htm*.tmp

getFlowKeyHash_SOURCES = getFlowKeyHash.c
getFlowKeyHash_LDFLAGS = -L../airframe/src -lairframe @GLIB_LIBS@ @libfixbuf_LIBS@
getFlowKeyHash_CFLAGS = @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

yafMeta2Pcap_SOURCES = yafMeta2Pcap.c
yafMeta2Pcap_LDFLAGS = @GLIB_LIBS@ @libfixbuf_LIBS@
yafMeta2Pcap_CFLAGS = @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

ipfixDump_SOURCES = ipfixDump.c ipfixDumpPrint.c
ipfixDump_LDFLAGS = @GLIB_LIBS@ @libfixbuf_LIBS@
ipfixDump_CFLAGS = @GLIB_CFLAGS@ @libfixbuf_CFLAGS@

yafzcbalance_SOURCES = yafzcbalance.c
yafzcbalance_LDFLAGS = -L../airframe/src -lairframe @GLIB_LIBS@ -lpthread
yafzcbalance_CFLAGS = @GLIB_CFLAGS@

noinst_HEADERS = ipfixDumpPrint.h infomodel.h

BUILT_SOURCES = infomodel.c infomodel.h
nodist_ipfixDump_SOURCES = infomodel.c infomodel.h
CLEANFILES += infomodel.c infomodel.h

RUN_MAKE_INFOMODEL = $(AM_V_GEN) \
 srcdir=$(top_builddir) ; \
 test -f $(top_builddir)/make-infomodel || srcdir=$(top_srcdir) ; \
 $(PERL) $${srcdir}/make-infomodel --package ipfixDump --dir-name=$(top_builddir)/infomodel $(INFOMODEL_REGISTRY_PREFIXES)

infomodel.c : infomodel.h
infomodel.h : $(top_builddir)/make-infomodel Makefile
	$(RUN_MAKE_INFOMODEL)
