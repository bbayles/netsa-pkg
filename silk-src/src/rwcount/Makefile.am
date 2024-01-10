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

bin_PROGRAMS = rwcount

EXTRA_DIST = rwcount.pod
if HAVE_POD2MAN
man1_MANS = rwcount.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwcount_SOURCES = rwcount.c rwcount.h rwcountsetup.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwcount-help.pl \
	tests/rwcount-version.pl \
	tests/rwcount-lone-command.pl \
	tests/rwcount-null-input.pl \
	tests/rwcount-b1-l1.pl \
	tests/rwcount-b30-l2.pl \
	tests/rwcount-b900-l3.pl \
	tests/rwcount-b3600.pl \
	tests/rwcount-b86400-l1.pl \
	tests/rwcount-b3600-l2.pl \
	tests/rwcount-start-epoch.pl \
	tests/rwcount-start-epoch-skip-0.pl \
	tests/rwcount-end-epoch.pl \
	tests/rwcount-start-epoch-week.pl \
	tests/rwcount-start-end-epoch.pl \
	tests/rwcount-milli-bin-start.pl \
	tests/rwcount-milli-bin.pl \
	tests/rwcount-reversed-input.pl \
	tests/rwcount-delimited.pl \
	tests/rwcount-no-columns.pl \
	tests/rwcount-column-sep.pl \
	tests/rwcount-legacy-0.pl \
	tests/rwcount-legacy-1.pl \
	tests/rwcount-empty-input.pl \
	tests/rwcount-empty-input-b3600.pl \
	tests/rwcount-multiple-inputs.pl \
	tests/rwcount-multiple-inputs-v6.pl \
	tests/rwcount-multiple-inputs-v4v6.pl \
	tests/rwcount-copy-input.pl \
	tests/rwcount-stdin.pl \
	tests/rwcount-b1800-l3.pl \
	tests/rwcount-b1800-l4.pl \
	tests/rwcount-b1800-l5.pl \
	tests/rwcount-b1800-l6.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwcount-no-switches.pl
