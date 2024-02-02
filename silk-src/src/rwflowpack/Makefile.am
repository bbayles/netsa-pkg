## Copyright (C) 2001-2023 by Carnegie Mellon University.
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

# Installed Targets

bin_PROGRAMS = rwpdu2silk
sbin_PROGRAMS = rwflowappend rwflowpack rwguess rwpackchecker

EXTRA_DIST = rwflowappend.pod rwflowpack.pod rwguess.pod \
	 rwpackchecker.pod rwpdu2silk.pod
if HAVE_POD2MAN
man1_MANS = rwpdu2silk.1
man8_MANS = rwflowappend.8 rwflowpack.8 rwguess.8 \
	 rwpackchecker.8
endif

pkginclude_HEADERS = rwflowpack.h

conf_files = rwflowappend.conf rwflowpack.conf
EXTRA_DIST += rwflowappend.conf.in rwflowpack.conf.in

init_d_scripts = rwflowappend.init.d rwflowpack.init.d
EXTRA_DIST += rwflowappend.init.d.in rwflowpack.init.d.in


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)

# source files common to rwflowpack and rwflowappend
common_sources = rwflow_utils.c rwflow_utils.h

rwflowappend_SOURCES = rwflowappend.c $(common_sources)
rwflowappend_LDADD = ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(PTHREAD_LDFLAGS)

rwflowpack_SOURCES = rwflowpack.c rwflowpack_priv.h \
	 stream-cache.c stream-cache.h \
	 dirreader.c fcfilesreader.c \
	 pdureader.c pdufilereader.c respoolreader.c \
	 $(common_sources) $(extra_sources)
EXTRA_rwflowpack_SOURCES = packlogic.c
extra_sources = $(extra_sources1) $(extra_sources2) $(extra_sources3) \
	 $(extra_sources4) $(extra_sources5) $(extra_sources6)
if HAVE_PACKING_LOGIC
# use static packing logic
extra_sources1 = packlogic.c
packlogic.$(OBJEXT): $(PACKING_LOGIC_PATH)
endif
if HAVE_FIXBUF
extra_sources2 = ipfixreader.c
endif
rwflowpack_LDADD = ../libflowsource/libflowsource.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)
rwflowpack_CPPFLAGS = $(SK_SRC_INCLUDES) $(FIXBUF_CFLAGS) $(SK_CPPFLAGS)

rwguess_SOURCES = rwguess.c 
rwguess_LDADD = ../libflowsource/libflowsource.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)

rwpackchecker_SOURCES = rwpackchecker.c
rwpackchecker_LDADD = ../libsilk/libsilk.la

rwpdu2silk_SOURCES = rwpdu2silk.c 
rwpdu2silk_LDADD = ../libflowsource/libflowsource.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)


rwflowappend.conf: Makefile rwflowappend.conf.in
	$(MAKE_CONF_FILE)
rwflowpack.conf: Makefile rwflowpack.conf.in
	$(MAKE_CONF_FILE)
rwflowappend.init.d: Makefile rwflowappend.init.d.in
	$(MAKE_INIT_D_SCRIPT)
rwflowpack.init.d: Makefile rwflowpack.init.d.in
	$(MAKE_INIT_D_SCRIPT)

all-local: $(conf_files) $(init_d_scripts)
install-data-local: install-conf-files install-init-d-scripts
uninstall-local: uninstall-conf-files uninstall-init-d-scripts

CLEANFILES = $(conf_files) $(init_d_scripts)

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(SILK_TESTPDU) $(SILK_TESTSETS)

EXTRA_DIST += $(TESTS)
EXTRA_DIST += \
	tests/rwflowappend-daemon.py \
	tests/rwflowpack-daemon.py \
	tests/rwflowpack-pack-pdu-dir.pl-ipv4.txt \
	tests/rwflowpack-pack-silk.pl-ipv4.txt \
	tests/rwflowpack-pack-silk.pl-ipv6.txt \
	tests/rwflowpack-pack-silk-discard.pl-ipv6.txt \
	tests/sensor77.conf \
	tests/sensors.conf

MOSTLYCLEANFILES = tests/rwflowappend-daemon.pyc tests/rwflowappend-daemon.pyc

TESTS = \
	tests/rwflowappend-help.pl \
	tests/rwflowappend-version.pl \
	tests/rwflowappend-lone-command.pl \
	tests/rwflowpack-help.pl \
	tests/rwflowpack-version.pl \
	tests/rwflowpack-lone-command.pl \
	tests/rwguess-help.pl \
	tests/rwguess-version.pl \
	tests/rwguess-lone-command.pl \
	tests/rwpackchecker-help.pl \
	tests/rwpackchecker-version.pl \
	tests/rwpackchecker-lone-command.pl \
	tests/rwpdu2silk-help.pl \
	tests/rwpdu2silk-version.pl \
	tests/rwpdu2silk-lone-command.pl \
	tests/rwguess-print-all.pl \
	tests/rwguess-small-input.pl \
	tests/rwguess-top-2.pl \
	tests/rwpackchecker-all-tests.pl \
	tests/rwpackchecker-port-123.pl \
	tests/rwpackchecker-bpp-allow-1.pl \
	tests/rwpackchecker-bpp-allow-2.pl \
	tests/rwpackchecker-sipset.pl \
	tests/rwpdu2silk-small-input.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwflowappend-init-d.pl \
	tests/rwflowpack-init-d.pl \
	tests/rwflowpack-sensorconf.pl \
	tests/rwflowpack-pack-silk.pl \
	tests/rwflowpack-pack-silk-ipv6.pl \
	tests/rwflowpack-pack-silk-send.pl \
	tests/rwflowpack-pack-silk-after.pl \
	tests/rwflowpack-pack-silk-cmd.pl \
	tests/rwflowpack-pack-fcfile.pl \
	tests/rwflowpack-pack-respool.pl \
	tests/rwflowpack-pack-pdu-dir.pl \
	tests/rwflowpack-pack-pdu-file.pl \
	tests/rwflowpack-pack-ipfix.pl \
	tests/rwflowpack-pack-ipfix-ipv6.pl \
	tests/rwflowpack-pack-ipfix-net-v4.pl \
	tests/rwflowpack-pack-ipfix-net-v6.pl \
	tests/rwflowpack-pack-multiple.pl \
	tests/rwflowpack-pack-multiple2.pl \
	tests/rwflowpack-pack-silk-discard-when.pl \
	tests/rwflowpack-pack-silk-discard-unless.pl \
	tests/rwflowpack-pack-silk-discard-when-ipset-v4.pl \
	tests/rwflowpack-pack-silk-discard-when-ipset-v6.pl \
	tests/rwflowpack-pack-bad-silk.pl \
	tests/rwflowpack-pack-bad-fcfile.pl \
	tests/rwflowpack-pack-bad-pdu.pl \
	tests/rwflowpack-pack-bad-ipfix.pl \
	tests/rwflowappend-append-ipv4.pl \
	tests/rwflowappend-append-ipv6.pl \
	tests/rwflowappend-append-cmd.pl \
	tests/rwflowappend-append-hours.pl \
	tests/rwflowappend-append-bad.pl \
	tests/rwflowpack-split-rwflowappend.pl
