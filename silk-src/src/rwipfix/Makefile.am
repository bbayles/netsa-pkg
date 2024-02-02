## Copyright (C) 2006-2023 by Carnegie Mellon University.
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
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $")

# Installed Targets

bin_PROGRAMS = rwipfix2silk rwsilk2ipfix
bin_SCRIPTS = rwp2yaf2silk

EXTRA_DIST = rwipfix2silk.pod rwsilk2ipfix.pod rwp2yaf2silk.in
if HAVE_POD2MAN
if HAVE_PODSELECT
# Perl files have POD embedded in the file which podselect extracts
src2pod2man = rwp2yaf2silk.1
endif
man1_MANS = rwipfix2silk.1 rwsilk2ipfix.1 $(src2pod2man)
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(FIXBUF_CFLAGS) $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libflowsource/libflowsource.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)

rwipfix2silk_SOURCES = rwipfix2silk.c

rwsilk2ipfix_SOURCES = rwsilk2ipfix.c

make_rwp2yaf2silk_edit = sed \
  -e 's|@PERL[@]|$(PERL)|g' \
  -e 's|@PACKAGE_STRING[@]|$(PACKAGE_STRING)|g' \
  -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
  -e 's|@SILK_VERSION_INTEGER[@]|$(SILK_VERSION_INTEGER)|g' \
  -e 's|@rwipfix2silk[@]|'$${my_rwipfix2silk}'|g'

MAKE_RWP2YAF2SILK = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$@.in || srcdir=$(srcdir)/ ; \
  my_rwipfix2silk=`echo rwipfix2silk | sed -e '$(transform)'` ; \
  $(make_rwp2yaf2silk_edit) "$${srcdir}$@.in" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

rwp2yaf2silk: Makefile rwp2yaf2silk.in
	$(MAKE_RWP2YAF2SILK)

rwp2yaf2silk.pod: rwp2yaf2silk.in
	$(AM_V_GEN)$(PODSELECT) $? > $@

MOSTLYCLEANFILES = rwp2yaf2silk.pod rwp2yaf2silk.tmp
CLEANFILES = rwp2yaf2silk

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwipfix2silk-help.pl \
	tests/rwipfix2silk-version.pl \
	tests/rwipfix2silk-lone-command.pl \
	tests/rwsilk2ipfix-help.pl \
	tests/rwsilk2ipfix-version.pl \
	tests/rwsilk2ipfix-lone-command.pl \
	tests/rwp2yaf2silk-help.pl \
	tests/rwp2yaf2silk-version.pl \
	tests/rwp2yaf2silk-lone-command.pl \
	tests/rwsilk2ipfix-to-and-fro-data.pl \
	tests/rwsilk2ipfix-to-and-fro-data-v6.pl \
	tests/rwsilk2ipfix-to-and-fro-empty.pl \
	tests/rwsilk2ipfix-to-and-fro-multiple.pl \
	tests/rwsilk2ipfix-to-and-fro-stdin.pl \
	tests/rwsilk2ipfix-print-stat.pl \
	tests/rwsilk2ipfix-print-stat-v6.pl \
	tests/rwipfix2silk-print-stat.pl \
	tests/rwipfix2silk-print-stat-v6.pl
