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

bin_PROGRAMS = rwcut

EXTRA_DIST = rwcut.pod
if HAVE_POD2MAN
man1_MANS = rwcut.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
if HAVE_PYTHON
silkpython = ../pysilk/libsilkpython.la
endif
LDADD =  $(silkpython) ../libsilk/libsilk.la $(PYTHON_LDFLAGS_EMBEDDED)

rwcut_SOURCES = rwcut.c rwcut.h rwcutsetup.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwcut-help.pl \
	tests/rwcut-version.pl \
	tests/rwcut-lone-command.pl \
	tests/rwcut-null-input.pl \
	tests/rwcut-sip-v4.pl \
	tests/rwcut-dip-v4.pl \
	tests/rwcut-5tuple-v4.pl \
	tests/rwcut-5tuple-v4-as-v6.pl \
	tests/rwcut-5tuple-v6.pl \
	tests/rwcut-bytes-pkt.pl \
	tests/rwcut-flag-fields.pl \
	tests/rwcut-stime.pl \
	tests/rwcut-time-fields.pl \
	tests/rwcut-site-fields.pl \
	tests/rwcut-misc-fields.pl \
	tests/rwcut-default-fields.pl \
	tests/rwcut-all-fields.pl \
	tests/rwcut-all-fields-v6.pl \
	tests/rwcut-dry-run.pl \
	tests/rwcut-rec-count1.pl \
	tests/rwcut-rec-count2.pl \
	tests/rwcut-rec-count3.pl \
	tests/rwcut-rec-count4.pl \
	tests/rwcut-rec-count5.pl \
	tests/rwcut-rec-count6.pl \
	tests/rwcut-rec-count7.pl \
	tests/rwcut-rec-count8.pl \
	tests/rwcut-rec-count-err1.pl \
	tests/rwcut-rec-count-err2.pl \
	tests/rwcut-rec-count-err3.pl \
	tests/rwcut-rec-count-err4.pl \
	tests/rwcut-rec-count-err5.pl \
	tests/rwcut-no-title.pl \
	tests/rwcut-no-final-del.pl \
	tests/rwcut-no-columns.pl \
	tests/rwcut-column-sep.pl \
	tests/rwcut-legacy-0.pl \
	tests/rwcut-legacy-1.pl \
	tests/rwcut-empty-input.pl \
	tests/rwcut-multiple-inputs.pl \
	tests/rwcut-multiple-inputs-v6.pl \
	tests/rwcut-copy-input.pl \
	tests/rwcut-stdin.pl \
	tests/rwcut-icmpTypeCode.pl \
	tests/rwcut-icmp-type.pl \
	tests/rwcut-icmpTypeCode-v6.pl \
	tests/rwcut-icmp-type-v6.pl \
	tests/rwcut-country-code.pl \
	tests/rwcut-country-code-v6.pl \
	tests/rwcut-address-types.pl \
	tests/rwcut-pmap-proto-port.pl \
	tests/rwcut-pmap-src-service-host.pl \
	tests/rwcut-pmap-dst-servhost.pl \
	tests/rwcut-pmap-multiple.pl \
	tests/rwcut-pmap-src-service-host-v6.pl \
	tests/rwcut-pmap-dst-servhost-v6.pl \
	tests/rwcut-pmap-multiple-v6.pl \
	tests/rwcut-int-ext-fields.pl \
	tests/rwcut-int-ext-fields-env.pl \
	tests/rwcut-int-ext-fields-v6.pl \
	tests/rwcut-skplugin-test.pl \
	tests/rwcut-pysilk-lower-port.pl \
	tests/rwcut-pysilk-lower-port2.pl \
	tests/rwcut-pysilk-private-ipv6.pl \
	tests/rwcut-pysilk-simple-reg.pl \
	tests/rwcut-pysilk-country.pl

EXTRA_TESTS = \
	tests/rwcut-flowrate.pl
EXTRA_DIST += $(EXTRA_TESTS)

if RUN_EXTRA_CHECKS
TESTS += $(EXTRA_TESTS)
endif
