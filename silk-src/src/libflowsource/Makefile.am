## Copyright (C) 2004-2023 by Carnegie Mellon University.
##
## @OPENSOURCE_LICENSE_START@
##
## SiLK 3.22.0
##
## Copyright 2023 Carnegie Mellon University.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
## INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
## UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
## AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
## PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
## THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
## INFRINGEMENT.
##
## Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
## contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for public
## release and unlimited distribution.  Please see Copyright notice for
## non-US Government use and distribution.
##
## GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##
## Contract No.: FA8702-15-D-0002
## Contractor Name: Carnegie Mellon University
## Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
## The Government's rights to use, modify, reproduce, release, perform,
## display, or disclose this software are restricted by paragraph (b)(2) of
## the Rights in Noncommercial Computer Software and Noncommercial Computer
## Software Documentation clause contained in the above identified
## contract. No restrictions apply after the expiration date shown
## above. Any reproduction of the software or portions thereof marked with
## this legend must also reproduce the markings.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
## Trademark Office by Carnegie Mellon University.
##
## This Software includes and/or makes use of Third-Party Software each
## subject to its own license.
##
## DM23-0973
##
## @OPENSOURCE_LICENSE_END@
##
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $");

SUBDIRS = infomodel

# Installed Targets

lib_LTLIBRARIES = libflowsource.la
libflowsource_version = 19:3:0
# At previous release: libflowsource_version = 19:3:0

EXTRA_DIST = sensor.conf.pod
if HAVE_POD2MAN
man5_MANS = sensor.conf.5
endif

pkginclude_HEADERS = libflowsource.h probeconf.h \
	 $(extra_headers1) $(extra_headers2) $(extra_headers3) \
	 $(extra_headers4) $(extra_headers5) $(extra_headers6)


# Dependencies on libfixbuf
if HAVE_FIXBUF
extra_check_programs = check-struct
nodist_sources2 = infomodel.c infomodel.h
extra_sources2 = ipfixsource.c ipfixsource.h skipfix.c skipfix.h
extra_headers2 =
endif

# Support for getting IPFIX elements from XML file(s)
EXTRA_DIST += xml2fixbuf.xslt make-infomodel

# script to generate infomodel.c and infomodel.h
RUN_MAKE_INFOMODEL = $(AM_V_GEN) \
  srcdir='' ; \
  test -f ./make-infomodel || srcdir=$(srcdir)/ ; \
  $(PERL) $${srcdir}make-infomodel --package $(PACKAGE) \
    $(INFOMODEL_REGISTRY_PREFIXES) || { rm -f $(nodist_sources2) ; exit 1 ; }

ipfixsource.$(OBJEXT) ipfixsource.lo: infomodel.h
infomodel.c: infomodel.h
infomodel.h: make-infomodel Makefile
	$(RUN_MAKE_INFOMODEL)


# Additional Targets

EXTRA_PROGRAMS = circbuf-test $(extra_check_programs)
# $(EXTRA_PROGRAMS) only need to appear in one of bin_PROGRAMS,
# noinst_PROGRAMS, or check_PROGRAMS
#check_PROGRAMS = $(EXTRA_PROGRAMS)
# Swap the comment character between bin_PROGRAMS and noinst_PROGRAMS
# to determine whether to install the test programs in $(bindir)
#bin_PROGRAMS += $(EXTRA_PROGRAMS)
noinst_PROGRAMS = $(EXTRA_PROGRAMS)


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(FIXBUF_CFLAGS) $(WARN_CFLAGS) $(SK_CFLAGS)
LDADD =	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)

libflowsource_la_SOURCES = circbuf.c circbuf.h \
	 pdusource.c udpsource.c udpsource.h probeconf.c \
	 probeconfparse.y probeconfscan.h probeconfscan.l v5pdu.h \
	 $(extra_sources1) $(extra_sources2) $(extra_sources3) \
	 $(extra_sources4) $(extra_sources5) $(extra_sources6)
nodist_libflowsource_la_SOURCES = \
	 $(nodist_sources1) $(nodist_sources2) $(nodist_sources3)
libflowsource_la_LDFLAGS = -version-info $(libflowsource_version)
#libflowsource_la_LIBADD  = $(LDADD)

check_struct_SOURCES = check-struct.c
check_struct_LDADD = libflowsource.la $(LDADD)

circbuf_test_SOURCES = circbuf-test.c
circbuf_test_LDADD = libflowsource.la $(LDADD)

# add switches to flex that remove unused functions
AM_LFLAGS = $(FLEX_NOFUNS)

AM_YFLAGS = -d
probeconfscan.$(OBJEXT) probeconfscan.lo: probeconfparse.h

CLEANFILES = $(EXTRA_PROGRAMS) $(nodist_libflowsource_la_SOURCES)

# Global Rules
include $(top_srcdir)/build.mk
