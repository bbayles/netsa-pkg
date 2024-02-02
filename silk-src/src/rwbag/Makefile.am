## Copyright (C) 2004-2023 by Carnegie Mellon University.
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
## RCSIDENT("$SiLK: Makefile.am c35222643509 2023-08-03 21:43:50Z mthomas $");

# Installed Targets

bin_PROGRAMS = rwbag rwbagbuild rwbagcat rwbagtool

EXTRA_DIST = rwbag.pod rwbagbuild.pod rwbagcat.pod rwbagtool.pod
if HAVE_POD2MAN
man1_MANS = rwbag.1 rwbagbuild.1 rwbagcat.1 rwbagtool.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwbag_SOURCES = rwbag.c

rwbagbuild_SOURCES = rwbagbuild.c

rwbagcat_SOURCES = rwbagcat.c

rwbagtool_SOURCES = rwbagtool.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(SILK_TESTBAGS)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwbag-help.pl \
	tests/rwbag-version.pl \
	tests/rwbag-lone-command.pl \
	tests/rwbagbuild-help.pl \
	tests/rwbagbuild-version.pl \
	tests/rwbagbuild-lone-command.pl \
	tests/rwbagcat-help.pl \
	tests/rwbagcat-version.pl \
	tests/rwbagcat-lone-command.pl \
	tests/rwbagtool-help.pl \
	tests/rwbagtool-version.pl \
	tests/rwbagtool-lone-command.pl \
	tests/rwbag-no-switches.pl \
	tests/rwbag-no-files.pl \
	tests/rwbag-null-input.pl \
	tests/rwbag-sip-flo.pl \
	tests/rwbag-sip-pkt.pl \
	tests/rwbag-sip-byt.pl \
	tests/rwbag-sip-flo-pkt.pl \
	tests/rwbag-sip-pkt-byt.pl \
	tests/rwbag-dip-flo.pl \
	tests/rwbag-dip-pkt.pl \
	tests/rwbag-dip-byt.pl \
	tests/rwbag-sport-flo.pl \
	tests/rwbag-sport-pkt.pl \
	tests/rwbag-sport-byt.pl \
	tests/rwbag-dport-flo.pl \
	tests/rwbag-dport-pkt.pl \
	tests/rwbag-dport-byt.pl \
	tests/rwbag-proto-flo.pl \
	tests/rwbag-proto-pkt.pl \
	tests/rwbag-proto-byt.pl \
	tests/rwbag-dport-flow.pl \
	tests/rwbag-empty-input.pl \
	tests/rwbag-empty-input-proto.pl \
	tests/rwbag-multiple-inputs.pl \
	tests/rwbag-multiple-inputs-v6.pl \
	tests/rwbag-multiple-inputs-v4v6.pl \
	tests/rwbag-stdin.pl \
	tests/rwbag-copy-input.pl \
	tests/rwbag-sip-flo-v6.pl \
	tests/rwbag-sip-pkt-v6.pl \
	tests/rwbag-sip-byt-v6.pl \
	tests/rwbag-sip-flo-pkt-v6.pl \
	tests/rwbag-sip-pkt-byt-v6.pl \
	tests/rwbag-dip-flo-v6.pl \
	tests/rwbag-dip-pkt-v6.pl \
	tests/rwbag-dip-byt-v6.pl \
	tests/rwbag-stime-byt.pl \
	tests/rwbag-sensor-pkt.pl \
	tests/rwbag-flags-flo.pl \
	tests/rwbag-scc-byt.pl \
	tests/rwbag-dcc-pkt-v6.pl \
	tests/rwbag-sippmap-flo.pl \
	tests/rwbag-dippmap-byt-v6.pl \
	tests/rwbag-dportpmap-pkt.pl \
	tests/rwbagcat-null-input.pl \
	tests/rwbagcat-bad-range-key.pl \
	tests/rwbagcat-bad-range-counter.pl \
	tests/rwbagcat-sport-mn-flo.pl \
	tests/rwbagcat-sport-mn-pkt.pl \
	tests/rwbagcat-sport-mn-byt.pl \
	tests/rwbagcat-sport-mx-flo.pl \
	tests/rwbagcat-sport-mx-pkt.pl \
	tests/rwbagcat-sport-mx-byt.pl \
	tests/rwbagcat-net-struct.pl \
	tests/rwbagcat-net-struct-ATS.pl \
	tests/rwbagcat-net-struct-12.pl \
	tests/rwbagcat-net-struct-b1-v4.pl \
	tests/rwbagcat-net-struct-b2-v4.pl \
	tests/rwbagcat-net-struct-14-b2-v4.pl \
	tests/rwbagcat-net-struct-v6.pl \
	tests/rwbagcat-net-struct-48-v6.pl \
	tests/rwbagcat-net-struct-60.pl \
	tests/rwbagcat-net-struct-b1-v6.pl \
	tests/rwbagcat-net-struct-b2-v6.pl \
	tests/rwbagcat-net-struct-b2-61-v6.pl \
	tests/rwbagcat-net-struct-b1-v4-b1-v6.pl \
	tests/rwbagcat-net-struct-v4-b3-v6.pl \
	tests/rwbagcat-bin-ips-linear.pl \
	tests/rwbagcat-bin-ips-binary.pl \
	tests/rwbagcat-bin-ips-decimal.pl \
	tests/rwbagcat-bin-ips-linear-v6.pl \
	tests/rwbagcat-bin-ips-binary-v6.pl \
	tests/rwbagcat-bin-ips-decimal-v6.pl \
	tests/rwbagcat-sort-count-sip-byt.pl \
	tests/rwbagcat-sort-count-pro-pkt-inc.pl \
	tests/rwbagcat-sort-count-pro-pkt-dec.pl \
	tests/rwbagtool-null-input.pl \
	tests/rwbagtool-bad-range-key.pl \
	tests/rwbagtool-bad-range-counter.pl \
	tests/rwbagtool-bad-scalarmultiply.pl \
	tests/rwbagtool-bad-backup-no-inplace.pl \
	tests/rwbagtool-bad-inplace-devnull.pl \
	tests/rwbagtool-mincounter.pl \
	tests/rwbagtool-maxcounter.pl \
	tests/rwbagtool-minkey.pl \
	tests/rwbagtool-maxkey.pl \
	tests/rwbagtool-add.pl \
	tests/rwbagtool-output-path.pl \
	tests/rwbagtool-invert.pl \
	tests/rwbagtool-coverset.pl \
	tests/rwbagtool-coverset-record-version.pl \
	tests/rwbagtool-invert-v6.pl \
	tests/rwbagtool-coverset-v6.pl \
	tests/rwbagtool-coverset-record-version-v6.pl \
	tests/rwbagtool-add-b1-b2-v4.pl \
	tests/rwbagtool-add-b2-b1-v4.pl \
	tests/rwbagtool-subtract-b1-b2-v4.pl \
	tests/rwbagtool-subtract-b2-b1-v4.pl \
	tests/rwbagtool-cmp-ge-b2-b1-v4.pl \
	tests/rwbagtool-cmp-le-b1-b2-v4.pl \
	tests/rwbagtool-cmp-eq-b1-b3-v4.pl \
	tests/rwbagtool-cmp-ge-b1-b3-v4.pl \
	tests/rwbagtool-minimize-b1-b3-v4.pl \
	tests/rwbagtool-maximize-b3-b1-v4.pl \
	tests/rwbagtool-divide-b1-b3-v4.pl \
	tests/rwbagtool-scalarmultiply-2-b1-v4.pl \
	tests/rwbagtool-intersect-b2-v4.pl \
	tests/rwbagtool-compl-intersect-b2-v4.pl \
	tests/rwbagtool-add-subtract-b1-b2-v4.pl \
	tests/rwbagtool-scalarmultiply-overflow1.pl \
	tests/rwbagtool-scalarmultiply-overflow2.pl \
	tests/rwbagtool-add-b1-b2-v6.pl \
	tests/rwbagtool-add-b2-b1-v6.pl \
	tests/rwbagtool-subtract-b1-b2-v6.pl \
	tests/rwbagtool-subtract-b2-b1-v6.pl \
	tests/rwbagtool-cmp-ge-b2-b1-v6.pl \
	tests/rwbagtool-cmp-le-b1-b2-v6.pl \
	tests/rwbagtool-cmp-eq-b1-b3-v6.pl \
	tests/rwbagtool-cmp-ge-b1-b3-v6.pl \
	tests/rwbagtool-minimize-b1-b3-v6.pl \
	tests/rwbagtool-maximize-b3-b1-v6.pl \
	tests/rwbagtool-divide-b1-b3-v6.pl \
	tests/rwbagtool-scalarmultiply-2-b1-v6.pl \
	tests/rwbagtool-intersect-b2-v6.pl \
	tests/rwbagtool-compl-intersect-b2-v6.pl \
	tests/rwbagtool-add-subtract-b1-b2-v6.pl \
	tests/rwbagtool-inplace-stdout.pl \
	tests/rwbagtool-inplace-noexist.pl \
	tests/rwbagtool-inplace-no-backup.pl \
	tests/rwbagtool-inplace-backup.pl \
	tests/rwbagbuild-null-input.pl \
	tests/rwbagbuild-bad-counter-overflow.pl \
	tests/rwbagbuild-bad-default-count.pl \
	tests/rwbagbuild-baginput.pl \
	tests/rwbagbuild-baginput-delim.pl \
	tests/rwbagbuild-setinput.pl \
	tests/rwbagbuild-setinput-count.pl \
	tests/rwbagbuild-output-path.pl \
	tests/rwbagbuild-baginput-v6.pl \
	tests/rwbagbuild-setinput-v6.pl \
	tests/rwbagbuild-proto-max.pl \
	tests/rwbagbuild-proto-overflow.pl \
	tests/rwbagbuild-port-max.pl \
	tests/rwbagbuild-port-overflow.pl \
	tests/rwbagbuild-empty-v6.pl \
	tests/rwbagbuild-counter-overflow.pl \
	tests/rwbagbuild-stime-byt.pl \
	tests/rwbagbuild-sensor-pkt.pl \
	tests/rwbagbuild-flags-flo.pl \
	tests/rwbagbuild-scc-byt.pl \
	tests/rwbagbuild-dcc-pkt-v6.pl \
	tests/rwbagbuild-sippmap-flo.pl \
	tests/rwbagbuild-dippmap-byt-v6.pl \
	tests/rwbagbuild-dportpmap-pkt.pl \
	tests/rwbagbuild-setinput-sippmap-flo.pl \
	tests/rwbagbuild-setinput-dcc-pkt-v6.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwbagtool-inplace-cleanup.pl \
	tests/rwbagtool-inplace-keep-temp.pl \
	tests/rwbagtool-notes.pl
