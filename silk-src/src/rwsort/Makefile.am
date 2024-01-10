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

bin_PROGRAMS = rwcombine rwdedupe rwsort

EXTRA_DIST = rwcombine.pod rwdedupe.pod rwsort.pod
if HAVE_POD2MAN
man1_MANS = rwcombine.1 rwdedupe.1 rwsort.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la
if HAVE_PYTHON
silkpython = ../pysilk/libsilkpython.la
endif

rwcombine_SOURCES = rwcombine.c rwcombine.h rwcombinesetup.c

rwdedupe_SOURCES = rwdedupe.c rwdedupe.h rwdedupesetup.c

rwsort_SOURCES = rwsort.c rwsort.h rwsortsetup.c
rwsort_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) $(SK_CPPFLAGS)
rwsort_LDADD = $(silkpython) $(LDADD) $(PYTHON_LDFLAGS_EMBEDDED)


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwsort-help.pl \
	tests/rwsort-version.pl \
	tests/rwsort-lone-command.pl \
	tests/rwsort-no-switches.pl \
	tests/rwsort-no-files.pl \
	tests/rwsort-null-input.pl \
	tests/rwsort-sip.pl \
	tests/rwsort-dip.pl \
	tests/rwsort-proto-ports.pl \
	tests/rwsort-reverse-packets.pl \
	tests/rwsort-bytes.pl \
	tests/rwsort-stime.pl \
	tests/rwsort-elapsed.pl \
	tests/rwsort-class-type-sensor.pl \
	tests/rwsort-empty-input.pl \
	tests/rwsort-empty-input-presorted.pl \
	tests/rwsort-empty-input-presorted-xargs.pl \
	tests/rwsort-multiple-inputs.pl \
	tests/rwsort-output-path.pl \
	tests/rwsort-stdin.pl \
	tests/rwsort-input-pipe.pl \
	tests/rwsort-sort-buffer.pl \
	tests/rwsort-presorted.pl \
	tests/rwsort-sip-v6.pl \
	tests/rwsort-dip-v6.pl \
	tests/rwsort-proto-ports-v6.pl \
	tests/rwsort-country-code-sip.pl \
	tests/rwsort-country-code-dip.pl \
	tests/rwsort-country-code-sip-v6.pl \
	tests/rwsort-country-code-dip-v6.pl \
	tests/rwsort-address-types-sip.pl \
	tests/rwsort-address-types-dip.pl \
	tests/rwsort-pmap-proto-port.pl \
	tests/rwsort-pmap-src-service-host.pl \
	tests/rwsort-pmap-dst-servhost.pl \
	tests/rwsort-pmap-multiple.pl \
	tests/rwsort-pmap-src-service-host-v6.pl \
	tests/rwsort-pmap-dst-servhost-v6.pl \
	tests/rwsort-pmap-multiple-v6.pl \
	tests/rwsort-int-ext-fields-ext.pl \
	tests/rwsort-int-ext-fields-int-v6.pl \
	tests/rwsort-flowrate-payload.pl \
	tests/rwsort-pysilk-key.pl \
	tests/rwsort-pysilk-simple-ipv4.pl \
	tests/rwsort-pysilk-simple-int.pl \
	tests/rwsort-pysilk-simple-enum.pl \
	tests/rwsort-pysilk-simple-ipv6.pl \
	tests/rwsort-rwuniq-nosort.pl \
	tests/rwsort-into-rwuniq.pl \
	tests/rwdedupe-help.pl \
	tests/rwdedupe-version.pl \
	tests/rwdedupe-lone-command.pl \
	tests/rwdedupe-no-switches.pl \
	tests/rwdedupe-no-files.pl \
	tests/rwdedupe-null-input.pl \
	tests/rwdedupe-empty-input.pl \
	tests/rwdedupe-one-copy.pl \
	tests/rwdedupe-two-copies.pl \
	tests/rwdedupe-buffer-size.pl \
	tests/rwdedupe-ignore-stime.pl \
	tests/rwdedupe-ignore-stime-v6.pl \
	tests/rwdedupe-one-copy-v6.pl \
	tests/rwdedupe-two-copies-v6.pl \
	tests/rwcombine-help.pl \
	tests/rwcombine-version.pl \
	tests/rwcombine-lone-command.pl \
	tests/rwcombine-no-switches.pl \
	tests/rwcombine-no-files.pl \
	tests/rwcombine-null-input.pl \
	tests/rwcombine-empty-input.pl \
	tests/rwcombine-empty-input-stats.pl \
	tests/rwcombine-standard-v4.pl \
	tests/rwcombine-standard-v4-stats.pl \
	tests/rwcombine-idle-time-v4.pl \
	tests/rwcombine-idle-time-v4-stats.pl \
	tests/rwcombine-buffer-idle-v4.pl \
	tests/rwcombine-buffer-idle-v4-stats.pl \
	tests/rwcombine-buffer-idle-v6.pl \
	tests/rwcombine-buffer-idle-v6-stats.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwsort-many-presorted.pl \
	tests/rwsort-skplugin-test.pl \
	tests/rwdedupe-mix-v4-v6.pl \
	tests/rwdedupe-mix-v4-v6-ignore.pl

EXTRA_TESTS = \
	tests/rwsort-flowrate-pps.pl \
	tests/rwsort-flowrate-bps.pl
EXTRA_DIST += $(EXTRA_TESTS)

if RUN_EXTRA_CHECKS
TESTS += $(EXTRA_TESTS)
endif
