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
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $");

# Installed Targets

bin_PROGRAMS = rwscan
if HAVE_PERL_DBI
have_dbi = rwscanquery
else
missing_dbi = rwscanquery
endif
bin_SCRIPTS = $(have_dbi)
noinst_SCRIPTS = $(missing_dbi)

EXTRA_DIST = rwscan.pod rwscanquery.in
if HAVE_POD2MAN
if HAVE_PODSELECT
if HAVE_PERL_DBI
# Perl files have POD embedded in the file which podselect extracts
src2pod2man = rwscanquery.1
endif
endif
man1_MANS = rwscan.1 $(src2pod2man)
endif

EXTRA_DIST += doc/db-mysql.sql doc/db-oracle.sql doc/db-postgres.sql


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la $(PTHREAD_LDFLAGS)

rwscan_SOURCES = rwscan.c rwscan.h rwscan_db.c rwscan_db.h \
	 rwscan_icmp.c rwscan_tcp.c rwscan_udp.c rwscan_utils.c \
	 rwscan_workqueue.c rwscan_workqueue.h

make_rwscanquery_edit = sed \
  -e 's|@PERL[@]|$(PERL)|g' \
  -e 's|@PACKAGE_STRING[@]|$(PACKAGE_STRING)|g' \
  -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
  -e 's|@SILK_VERSION_INTEGER[@]|$(SILK_VERSION_INTEGER)|g' \
  -e 's|@rwfilter[@]|'$${my_rwfilter}'|g' \
  -e 's|@rwset[@]|'$${my_rwset}'|g' \
  -e 's|@rwsetbuild[@]|'$${my_rwsetbuild}'|g' \
  -e 's|@rwsetcat[@]|'$${my_rwsetcat}'|g'

MAKE_RWSCANQUERY = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$@.in || srcdir=$(srcdir)/ ; \
  my_rwfilter=`echo rwfilter | sed -e '$(transform)'` ; \
  my_rwset=`echo rwset | sed -e '$(transform)'` ; \
  my_rwsetbuild=`echo rwsetbuild | sed -e '$(transform)'` ; \
  my_rwsetcat=`echo rwsetcat | sed -e '$(transform)'` ; \
  $(make_rwscanquery_edit) "$${srcdir}$@.in" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

rwscanquery: Makefile rwscanquery.in
	$(MAKE_RWSCANQUERY)

rwscanquery.pod : rwscanquery.in
	$(AM_V_GEN)$(PODSELECT) $? > $@

MOSTLYCLEANFILES = rwscanquery.pod rwscanquery.tmp
CLEANFILES = rwscanquery 

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(SILK_TESTSCAN)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwscan-help.pl \
	tests/rwscan-version.pl \
	tests/rwscan-lone-command.pl \
	tests/rwscan-null-input-blr.pl \
	tests/rwscan-missing-set-arg.pl \
	tests/rwscan-empty-input.pl \
	tests/rwscan-empty-input-blr.pl \
	tests/rwscan-hybrid.pl \
	tests/rwscan-trw-only.pl \
	tests/rwscan-blr-only.pl \
	tests/rwscanquery-help.pl \
	tests/rwscanquery-version.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwscanquery-sqlite.pl
