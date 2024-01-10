## Copyright (C) 2005-2023 by Carnegie Mellon University.
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

bin_PROGRAMS = rwgroup

EXTRA_DIST = rwgroup.pod
if HAVE_POD2MAN
man1_MANS = rwgroup.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
if HAVE_PYTHON
silkpython = ../pysilk/libsilkpython.la
endif
LDADD =  $(silkpython) ../libsilk/libsilk.la $(PYTHON_LDFLAGS_EMBEDDED)

rwgroup_SOURCES = rwgroup.c rwgroup.h rwgroupsetup.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwgroup-help.pl \
	tests/rwgroup-version.pl \
	tests/rwgroup-lone-command.pl \
	tests/rwgroup-null-input.pl \
	tests/rwgroup-too-many-args.pl \
	tests/rwgroup-no-delta-value.pl \
	tests/rwgroup-no-delta-field.pl \
	tests/rwgroup-empty-input.pl \
	tests/rwgroup-sport.pl \
	tests/rwgroup-sport-thresh.pl \
	tests/rwgroup-ipdelta.pl \
	tests/rwgroup-ports-delta.pl \
	tests/rwgroup-ips.pl \
	tests/rwgroup-ips-delta.pl \
	tests/rwgroup-ips-del-sum.pl \
	tests/rwgroup-ips-del-sum-thresh.pl \
	tests/rwgroup-ipdelta-v6.pl \
	tests/rwgroup-ips-v6.pl \
	tests/rwgroup-ips-del-sum-thresh-v6.pl \
	tests/rwgroup-country-code-sip.pl \
	tests/rwgroup-country-code-dip.pl \
	tests/rwgroup-address-types-sip.pl \
	tests/rwgroup-address-types-dip.pl \
	tests/rwgroup-pmap-proto-port.pl \
	tests/rwgroup-pmap-src-service-host.pl \
	tests/rwgroup-pmap-dst-servhost.pl \
	tests/rwgroup-pmap-multiple.pl \
	tests/rwgroup-pmap-src-service-host-v6.pl \
	tests/rwgroup-pmap-dst-servhost-v6.pl \
	tests/rwgroup-pmap-multiple-v6.pl \
	tests/rwgroup-flowrate-payload.pl \
	tests/rwgroup-pysilk-key.pl \
	tests/rwgroup-rwuniq-direct.pl \
	tests/rwgroup-into-rwuniq.pl

EXTRA_TESTS = \
	tests/rwgroup-flowrate-pps.pl \
	tests/rwgroup-flowrate-bps.pl
EXTRA_DIST += $(EXTRA_TESTS)

if RUN_EXTRA_CHECKS
TESTS += $(EXTRA_TESTS)
endif
