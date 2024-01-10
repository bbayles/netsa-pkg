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

bin_PROGRAMS = rwstats rwuniq

EXTRA_DIST = rwstats.pod rwuniq.pod
if HAVE_POD2MAN
man1_MANS = rwstats.1 rwuniq.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
if HAVE_PYTHON
silkpython = ../pysilk/libsilkpython.la
endif
LDADD =  $(silkpython) ../libsilk/libsilk.la $(PYTHON_LDFLAGS_EMBEDDED)

STATSUNIQ = rwstats.h rwstatssetup.c skunique.c skunique.h

rwstats_SOURCES = $(STATSUNIQ) rwstats.c \
	interval.h intervalstats.c rwstatslegacy.c rwstatsproto.c

rwuniq_SOURCES = $(STATSUNIQ) rwuniq.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

if RUN_EXTRA_CHECKS
more_data = $(SILK_TESTSIPS004)
endif

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(more_data)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwstats-help.pl \
	tests/rwstats-legacy-help.pl \
	tests/rwstats-version.pl \
	tests/rwstats-lone-command.pl \
	tests/rwstats-no-switches.pl \
	tests/rwstats-no-files.pl \
	tests/rwstats-null-input.pl \
	tests/rwstats-sip-top-flo-p4.pl \
	tests/rwstats-dip-top-flo-p4.pl \
	tests/rwstats-sip-top-byt-c100.pl \
	tests/rwstats-dip-top-pkt-t25000.pl \
	tests/rwstats-sdip-top-byt-c2.pl \
	tests/rwstats-sip24-top-pkt-p2.pl \
	tests/rwstats-sip24-top-pkt-p1.pl \
	tests/rwstats-dip16-bot-byt-c10.pl \
	tests/rwstats-sip-top-flo-p4-v6.pl \
	tests/rwstats-dip-top-pkt-t25000-v6.pl \
	tests/rwstats-sdip-top-byt-c2-v6.pl \
	tests/rwstats-sport-top-flo-p5.pl \
	tests/rwstats-dport-top-flo-t8000.pl \
	tests/rwstats-sdport-top-flo-c5.pl \
	tests/rwstats-sport-sip-pkt-byt-c10.pl \
	tests/rwstats-proto-top-pkt-c15.pl \
	tests/rwstats-proto-bot-pkt-c15.pl \
	tests/rwstats-sport-sip-dist-t5000.pl \
	tests/rwstats-dport-dip-dist-t5000.pl \
	tests/rwstats-proto-sdip-dist-c5.pl \
	tests/rwstats-proto-sdip-dist-c5-v6.pl \
	tests/rwstats-bin-time-stime.pl \
	tests/rwstats-bin-time-etime.pl \
	tests/rwstats-bin-time-stime-etime.pl \
	tests/rwstats-bin-time-stime-etime-dur.pl \
	tests/rwstats-integer-ips.pl \
	tests/rwstats-no-titles.pl \
	tests/rwstats-no-columns.pl \
	tests/rwstats-column-sep.pl \
	tests/rwstats-delimited.pl \
	tests/rwstats-proto-stats.pl \
	tests/rwstats-overall-stats.pl \
	tests/rwstats-empty-input.pl \
	tests/rwstats-empty-input-presorted.pl \
	tests/rwstats-empty-input-presorted-xargs.pl \
	tests/rwstats-multiple-inputs.pl \
	tests/rwstats-multiple-inputs-v6.pl \
	tests/rwstats-multiple-inputs-v4v6.pl \
	tests/rwstats-copy-input.pl \
	tests/rwstats-stdin.pl \
	tests/rwstats-icmp-top-byt-p5.pl \
	tests/rwstats-dport-icmp-top-p16.pl \
	tests/rwstats-icmp-dport-top-p16.pl \
	tests/rwstats-sport-bot-flo-c4.pl \
	tests/rwstats-dport-bot-byt-c4.pl \
	tests/rwstats-multi-inputs-3-5.pl \
	tests/rwstats-multi-inputs-3-5-pre.pl \
	tests/rwstats-country-code-sip.pl \
	tests/rwstats-country-code-dip.pl \
	tests/rwstats-country-code-sip-v6.pl \
	tests/rwstats-country-code-dip-v6.pl \
	tests/rwstats-address-types-sip.pl \
	tests/rwstats-address-types-dip.pl \
	tests/rwstats-pmap-proto-port.pl \
	tests/rwstats-pmap-src-service-host.pl \
	tests/rwstats-pmap-dst-servhost.pl \
	tests/rwstats-pmap-multiple.pl \
	tests/rwstats-pmap-src-service-host-v6.pl \
	tests/rwstats-pmap-dst-servhost-v6.pl \
	tests/rwstats-pmap-multiple-v6.pl \
	tests/rwstats-int-ext-fields-ext.pl \
	tests/rwstats-int-ext-fields-int-v6.pl \
	tests/rwstats-flowrate-payload.pl \
	tests/rwstats-skplugin-test.pl \
	tests/rwstats-pysilk-key.pl \
	tests/rwstats-pysilk-value.pl \
	tests/rwstats-pysilk-key-value.pl \
	tests/rwstats-pysilk-simple-agg.pl \
	tests/rwuniq-help.pl \
	tests/rwuniq-version.pl \
	tests/rwuniq-lone-command.pl \
	tests/rwuniq-no-switches.pl \
	tests/rwuniq-null-input.pl \
	tests/rwuniq-no-files.pl \
	tests/rwuniq-ports-proto-unix-sort.pl \
	tests/rwuniq-ports-proto-sorted.pl \
	tests/rwuniq-ports-proto-sorted-v6.pl \
	tests/rwuniq-ports-proto-presorted.pl \
	tests/rwuniq-ports-proto-multi-pre.pl \
	tests/rwuniq-sip-bytes.pl \
	tests/rwuniq-dip-bytes.pl \
	tests/rwuniq-dip-packets.pl \
	tests/rwuniq-sip-bytes-v6.pl \
	tests/rwuniq-dip-packets-v6.pl \
	tests/rwuniq-dport-all.pl \
	tests/rwuniq-stime-packets-flows.pl \
	tests/rwuniq-bin-time-stime.pl \
	tests/rwuniq-bin-time-etime.pl \
	tests/rwuniq-bin-time-stime-etime.pl \
	tests/rwuniq-bin-time-stime-etime-dur.pl \
	tests/rwuniq-bin-time-stime-dur.pl \
	tests/rwuniq-elapsed-bytes.pl \
	tests/rwuniq-etime.pl \
	tests/rwuniq-stime-proto-sorted.pl \
	tests/rwuniq-collection-point.pl \
	tests/rwuniq-proto.pl \
	tests/rwuniq-sport-mn-rec.pl \
	tests/rwuniq-sport-mn-pkt.pl \
	tests/rwuniq-sport-mn-byt.pl \
	tests/rwuniq-sport-mx-rec.pl \
	tests/rwuniq-sport-mx-pkt.pl \
	tests/rwuniq-sport-mx-byt.pl \
	tests/rwuniq-sport-count-sip.pl \
	tests/rwuniq-sport-count-sip-v6.pl \
	tests/rwuniq-sport-count-sip-dip.pl \
	tests/rwuniq-sport-count-sip-pre.pl \
	tests/rwuniq-sport-count-sip-dip-pre.pl \
	tests/rwuniq-sport-count-sip-dip-v6.pl \
	tests/rwuniq-sport-count2-sip-dip-v6.pl \
	tests/rwuniq-sport-count-sip-pre-v6.pl \
	tests/rwuniq-no-title.pl \
	tests/rwuniq-no-column.pl \
	tests/rwuniq-delimited.pl \
	tests/rwuniq-legacytime-0.pl \
	tests/rwuniq-legacytime-1.pl \
	tests/rwuniq-empty-input.pl \
	tests/rwuniq-empty-input-presorted.pl \
	tests/rwuniq-empty-input-presorted-xargs.pl \
	tests/rwuniq-multiple-inputs.pl \
	tests/rwuniq-copy-input.pl \
	tests/rwuniq-stdin.pl \
	tests/rwuniq-icmpTypeCode.pl \
	tests/rwuniq-dport-icmp.pl \
	tests/rwuniq-icmp-dport.pl \
	tests/rwuniq-country-code-sip.pl \
	tests/rwuniq-country-code-dip.pl \
	tests/rwuniq-country-code-sip-v6.pl \
	tests/rwuniq-country-code-dip-v6.pl \
	tests/rwuniq-address-types-sip.pl \
	tests/rwuniq-address-types-dip.pl \
	tests/rwuniq-address-stype-proto-sorted.pl \
	tests/rwuniq-pmap-proto-port.pl \
	tests/rwuniq-pmap-src-service-host.pl \
	tests/rwuniq-pmap-dst-servhost.pl \
	tests/rwuniq-pmap-multiple.pl \
	tests/rwuniq-pmap-src-service-host-v6.pl \
	tests/rwuniq-pmap-dst-servhost-v6.pl \
	tests/rwuniq-pmap-multiple-v6.pl \
	tests/rwuniq-int-ext-fields-ext.pl \
	tests/rwuniq-int-ext-fields-int-v6.pl \
	tests/rwuniq-flowrate-payload.pl \
	tests/rwuniq-skplugin-test.pl \
	tests/rwuniq-pysilk-key.pl \
	tests/rwuniq-pysilk-value.pl \
	tests/rwuniq-pysilk-key-value.pl \
	tests/rwuniq-pysilk-simple-agg.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwstats-many-presorted.pl \
	tests/rwuniq-many-presorted.pl

EXTRA_TESTS = \
	tests/rwstats-dist-sip-random.pl \
	tests/rwstats-dist-sip-presort.pl \
	tests/rwstats-flowrate-pps.pl \
	tests/rwstats-flowrate-bps.pl \
	tests/rwuniq-many-dist-random.pl \
	tests/rwuniq-many-dist-presort.pl \
	tests/rwuniq-flowrate-pps.pl \
	tests/rwuniq-flowrate-bps.pl
EXTRA_DIST += $(EXTRA_TESTS)

if RUN_EXTRA_CHECKS
TESTS += $(EXTRA_TESTS)
endif
