## Copyright (C) 2007-2023 by Carnegie Mellon University.
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

bin_PROGRAMS = rwipaexport rwipaimport

EXTRA_DIST = rwipaexport.pod rwipaimport.pod ipafilter.pod
if HAVE_POD2MAN
man1_MANS = rwipaexport.1 rwipaimport.1
man3_MANS = ipafilter.3
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(LIBIPA_CFLAGS) $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la $(LIBIPA_LDFLAGS)

if HAVE_STATIC_APPLICATIONS
ipafilter_libs = $(LDADD)
else
ipafilter_libs = 
endif

rwipaexport_SOURCES = rwipa.h rwipaexport.c rwipautils.c
rwipaexport_CFLAGS = $(AM_CFLAGS)

rwipaimport_SOURCES = rwipa.h rwipaimport.c rwipautils.c
rwipaimport_CFLAGS = $(AM_CFLAGS)


pkglib_LTLIBRARIES = ipafilter.la

ipafilter_la_SOURCES = ipafilter.c rwipautils.c
ipafilter_la_LDFLAGS = -module -avoid-version
ipafilter_la_LIBADD = $(ipafilter_libs) $(LIBIPA_LDFLAGS)


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwipaexport-help.pl \
	tests/rwipaexport-version.pl \
	tests/rwipaexport-lone-command.pl \
	tests/rwipaexport-no-catalog.pl \
	tests/rwipaimport-help.pl \
	tests/rwipaimport-version.pl \
	tests/rwipaimport-lone-command.pl \
	tests/rwipaimport-no-catalog.pl \
	tests/rwipaimport-no-endtime.pl \
	tests/rwipaimport-no-starttime.pl \
	tests/rwipaimport-no-config.pl \
	tests/rwipaexport-no-config.pl
