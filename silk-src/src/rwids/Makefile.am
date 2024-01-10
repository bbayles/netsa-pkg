## Copyright (C) 2008-2023 by Carnegie Mellon University.
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

if HAVE_PYTHONBIN
bin_SCRIPTS = rwidsquery
endif

EXTRA_DIST = rwidsquery.pod
if HAVE_POD2MAN
if HAVE_PYTHONBIN
man1_MANS = rwidsquery.1
endif
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)

EXTRA_DIST += rwidsquery.in rwidsquery24.in

if HAVE_PYTHON24
rwidsquery_tmpl = rwidsquery24.in
else
rwidsquery_tmpl = rwidsquery.in
endif

make_rwidsquery_edit = sed \
  -e 's|@PYTHON[@]|$(PYTHON)|g' \
  -e 's|@PACKAGE_STRING[@]|$(PACKAGE_STRING)|g' \
  -e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
  -e 's|@rwfilter[@]|'$${my_rwfilter}'|g'

MAKE_RWIDSQUERY = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$(rwidsquery_tmpl) || srcdir=$(srcdir)/ ; \
  my_rwfilter=`echo rwfilter | sed -e '$(transform)'` ; \
  $(make_rwidsquery_edit) "$${srcdir}$(rwidsquery_tmpl)" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

rwidsquery: Makefile $(rwidsquery_tmpl)
	$(MAKE_RWIDSQUERY)

MOSTLYCLEANFILES = rwidsquery.tmp
CLEANFILES = rwidsquery

# Global Rules
include $(top_srcdir)/build.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwidsquery-help.pl \
	tests/rwidsquery-version.pl \
	tests/rwidsquery-lone-command.pl \
	tests/rwidsquery-no-input.pl \
	tests/rwidsquery-fast.pl \
	tests/rwidsquery-full.pl \
	tests/rwidsquery-rule.pl \
	tests/rwidsquery-rule-no-date.pl
