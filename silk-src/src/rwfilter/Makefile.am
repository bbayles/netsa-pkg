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

bin_PROGRAMS = rwfilter rwfglob

EXTRA_DIST = rwfilter.pod rwfglob.pod
if HAVE_POD2MAN
man1_MANS = rwfilter.1 rwfglob.1
endif


# Build Rules

if HAVE_PYTHON
silkpython = ../pysilk/libsilkpython.la
endif

MYCC = @CC@
rwfilter_extra =
cppflags_extra =
ldadd_common = ../libsilk/libsilk.la
ldadd_rwfilter = $(silkpython) $(ldadd_common) \
	 $(PYTHON_LDFLAGS_EMBEDDED) $(PTHREAD_LDFLAGS)

CC = $(MYCC)
AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) \
	$(SK_CPPFLAGS) $(cppflags_extra)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)

rwfglob_SOURCES = fglob.c rwfglobapp.c
rwfglob_LDADD = $(ldadd_common)

rwfilter_SOURCES = fglob.c rwfilter.c rwfilter.h \
	 rwfiltercheck.c rwfiltersetup.c rwfilterthread.c rwfiltertuple.c \
	 $(rwfilter_extra)
rwfilter_LDADD = $(ldadd_rwfilter)


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwfilter-help.pl \
	tests/rwfilter-version.pl \
	tests/rwfilter-lone-command.pl \
	tests/rwfglob-help.pl \
	tests/rwfglob-version.pl \
	tests/rwfglob-lone-command.pl \
	tests/rwfglob-start-hour.pl \
	tests/rwfglob-start-end-hour.pl \
	tests/rwfglob-start-day.pl \
	tests/rwfglob-sensor-name.pl \
	tests/rwfglob-sensor-list.pl \
	tests/rwfglob-class.pl \
	tests/rwfglob-type.pl \
	tests/rwfglob-flowtype.pl \
	tests/rwfglob-type-sensor.pl \
	tests/rwfglob-bad-range.pl \
	tests/rwfglob-at-sensor.pl \
	tests/rwfglob-at-type.pl \
	tests/rwfglob-at-flowtype.pl \
	tests/rwfglob-at-type-sensor.pl \
	tests/rwfilter-null-input.pl \
	tests/rwfilter-no-input.pl \
	tests/rwfilter-no-output.pl \
	tests/rwfilter-no-fltr-pass.pl \
	tests/rwfilter-no-filtr-fail.pl \
	tests/rwfilter-no-fltr-stats.pl \
	tests/rwfilter-fglob.pl \
	tests/rwfilter-sport.pl \
	tests/rwfilter-tuple-fwd.pl \
	tests/rwfilter-dp-25.pl \
	tests/rwfilter-tuple-rev.pl \
	tests/rwfilter-ap-25.pl \
	tests/rwfilter-tuple-both.pl \
	tests/rwfilter-sp-dp-25.pl \
	tests/rwfilter-empty.pl \
	tests/rwfilter-bytes.pl \
	tests/rwfilter-packets.pl \
	tests/rwfilter-bpp.pl \
	tests/rwfilter-duration.pl \
	tests/rwfilter-stime.pl \
	tests/rwfilter-etime.pl \
	tests/rwfilter-active-time.pl \
	tests/rwfilter-proto.pl \
	tests/rwfilter-print-stats-file.pl \
	tests/rwfilter-print-volume.pl \
	tests/rwfilter-print-volume-v6.pl \
	tests/rwfilter-scidr-fail.pl \
	tests/rwfilter-not-scidr-pass.pl \
	tests/rwfilter-saddr-fail.pl \
	tests/rwfilter-not-saddr-pass.pl \
	tests/rwfilter-sipset-fail.pl \
	tests/rwfilter-not-sipset-pass.pl \
	tests/rwfilter-any-cidr-fail.pl \
	tests/rwfilter-not-any-cidr-pass.pl \
	tests/rwfilter-any-addr-fail.pl \
	tests/rwfilter-not-any-addr-pass.pl \
	tests/rwfilter-anyset-fail.pl \
	tests/rwfilter-not-anyset-pass.pl \
	tests/rwfilter-max-pass.pl \
	tests/rwfilter-max-fail.pl \
	tests/rwfilter-max-pass-fail.pl \
	tests/rwfilter-type.pl \
	tests/rwfilter-icmp-type.pl \
	tests/rwfilter-icmp-code.pl \
	tests/rwfilter-flags-all.pl \
	tests/rwfilter-flags-init.pl \
	tests/rwfilter-flags-sess.pl \
	tests/rwfilter-flags-sess2.pl \
	tests/rwfilter-attributes.pl \
	tests/rwfilter-attributes2.pl \
	tests/rwfilter-application.pl \
	tests/rwfilter-ip-version.pl \
	tests/rwfilter-input-index.pl \
	tests/rwfilter-output-index.pl \
	tests/rwfilter-scidr-fail-v6.pl \
	tests/rwfilter-not-scidr-pass-v6.pl \
	tests/rwfilter-saddr-fail-v6.pl \
	tests/rwfilter-not-saddr-pass-v6.pl \
	tests/rwfilter-any-cidr-fail-v6.pl \
	tests/rwfilter-not-any-cidr-pass-v6.pl \
	tests/rwfilter-any-addr-fail-v6.pl \
	tests/rwfilter-not-any-addr-pass-v6.pl \
	tests/rwfilter-at-type.pl \
	tests/rwfilter-at-fglob.pl \
	tests/rwfilter-scc.pl \
	tests/rwfilter-dcc.pl \
	tests/rwfilter-scc-dcc.pl \
	tests/rwfilter-scc-v6.pl \
	tests/rwfilter-dcc-v6.pl \
	tests/rwfilter-scc-dcc-v6.pl \
	tests/rwfilter-stype-1.pl \
	tests/rwfilter-dtype-2.pl \
	tests/rwfilter-sport-dhcp.pl \
	tests/rwfilter-dport-http.pl \
	tests/rwfilter-sip-ntp.pl \
	tests/rwfilter-dip-internal.pl \
	tests/rwfilter-anyip-dhcp.pl \
	tests/rwfilter-two-pmaps.pl \
	tests/rwfilter-sip-ntp-v6.pl \
	tests/rwfilter-dip-internal-v6.pl \
	tests/rwfilter-anyip-dhcp-v6.pl \
	tests/rwfilter-two-pmaps-v6.pl \
	tests/rwfilter-flowrate-loaded-unused.pl \
	tests/rwfilter-payload-bytes.pl \
	tests/rwfilter-ipafilter-loaded-unused.pl \
	tests/rwfilter-python-loaded-unused.pl \
	tests/rwfilter-python-expr.pl \
	tests/rwfilter-python-file.pl \
	tests/rwfilter-multiple.pl \
	tests/rwfilter-stdin.pl \
	tests/rwfilter-xargs.pl \
	tests/rwfilter-threads.pl

EXTRA_TESTS = \
	tests/rwfilter-flowrate-bps.pl \
	tests/rwfilter-flowrate-pps.pl \
	tests/rwfilter-payload-rate.pl
EXTRA_DIST += $(EXTRA_TESTS)

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwfglob-times.pl

if RUN_EXTRA_CHECKS
TESTS += $(EXTRA_TESTS)
endif
