## Copyright (C) 2016-2023 by Carnegie Mellon University.
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
## RCSIDENT("$SiLK: Makefile.am 0e0426562cda 2023-09-05 21:34:53Z mthomas $");

# Installed Targets

bin_PROGRAMS = rwaggbag rwaggbagbuild rwaggbagcat rwaggbagtool

EXTRA_DIST = rwaggbag.pod rwaggbagbuild.pod rwaggbagcat.pod rwaggbagtool.pod
if HAVE_POD2MAN
man1_MANS = rwaggbag.1 rwaggbagbuild.1 rwaggbagcat.1 rwaggbagtool.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwaggbag_SOURCES = rwaggbag.c

rwaggbagbuild_SOURCES = rwaggbagbuild.c

rwaggbagcat_SOURCES = rwaggbagcat.c

rwaggbagtool_SOURCES = rwaggbagtool.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(SILK_TESTBAGS)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwaggbag-help.pl \
	tests/rwaggbag-help-fields.pl \
	tests/rwaggbag-version.pl \
	tests/rwaggbag-lone-command.pl \
	tests/rwaggbagbuild-help.pl \
	tests/rwaggbagbuild-help-fields.pl \
	tests/rwaggbagbuild-version.pl \
	tests/rwaggbagbuild-lone-command.pl \
	tests/rwaggbagcat-help.pl \
	tests/rwaggbagcat-help-fields.pl \
	tests/rwaggbagcat-version.pl \
	tests/rwaggbagcat-lone-command.pl \
	tests/rwaggbagtool-help.pl \
	tests/rwaggbagtool-help-fields.pl \
	tests/rwaggbagtool-version.pl \
	tests/rwaggbagtool-lone-command.pl \
	tests/rwaggbag-no-switches.pl \
	tests/rwaggbag-null-input.pl \
	tests/rwaggbag-no-files.pl \
	tests/rwaggbag-ports-proto.pl \
	tests/rwaggbag-ports-proto-v6.pl \
	tests/rwaggbag-ports-proto-multi.pl \
	tests/rwaggbag-sipv4-bytes.pl \
	tests/rwaggbag-dipv4-bytes.pl \
	tests/rwaggbag-dipv4-packets.pl \
	tests/rwaggbag-sipv6-bytes.pl \
	tests/rwaggbag-dipv6-packets.pl \
	tests/rwaggbag-dport-all.pl \
	tests/rwaggbag-stime-packets-records.pl \
	tests/rwaggbag-elapsed-bytes.pl \
	tests/rwaggbag-etime.pl \
	tests/rwaggbag-stime-proto.pl \
	tests/rwaggbag-collection-point.pl \
	tests/rwaggbag-proto.pl \
	tests/rwaggbag-no-title.pl \
	tests/rwaggbag-no-column.pl \
	tests/rwaggbag-delimited.pl \
	tests/rwaggbag-empty-input.pl \
	tests/rwaggbag-empty-input-xargs.pl \
	tests/rwaggbag-multiple-inputs.pl \
	tests/rwaggbag-copy-input.pl \
	tests/rwaggbag-stdin.pl \
	tests/rwaggbag-icmpTypeCode.pl \
	tests/rwaggbag-dport-icmp.pl \
	tests/rwaggbag-icmp-dport.pl \
	tests/rwaggbag-country-code-sip.pl \
	tests/rwaggbag-country-code-dip.pl \
	tests/rwaggbag-country-code-sip-v6.pl \
	tests/rwaggbag-country-code-dip-v6.pl \
	tests/rwaggbagbuild-no-switches.pl \
	tests/rwaggbagbuild-null-input.pl \
	tests/rwaggbagbuild-no-files.pl \
	tests/rwaggbagbuild-ports-proto.pl \
	tests/rwaggbagbuild-ports-proto-v6.pl \
	tests/rwaggbagbuild-sipv4-bytes.pl \
	tests/rwaggbagbuild-dipv4-bytes.pl \
	tests/rwaggbagbuild-dipv4-packets.pl \
	tests/rwaggbagbuild-sipv6-bytes.pl \
	tests/rwaggbagbuild-stime-packets-records.pl \
	tests/rwaggbagbuild-etime.pl \
	tests/rwaggbagbuild-stime-proto.pl \
	tests/rwaggbagbuild-collection-point.pl \
	tests/rwaggbagbuild-country-code-sip.pl \
	tests/rwaggbagbuild-country-code-dip.pl \
	tests/rwaggbagbuild-country-code-aggbagcat.pl \
	tests/rwaggbagcat-null-input.pl \
	tests/rwaggbagcat-bad-fields.pl \
	tests/rwaggbagcat-bad-missing.pl \
	tests/rwaggbagcat-fields-bad-missing.pl \
	tests/rwaggbagcat-no-fields.pl \
	tests/rwaggbagcat-fields-exact.pl \
	tests/rwaggbagcat-fields-subset.pl \
	tests/rwaggbagcat-fields-superset.pl \
	tests/rwaggbagcat-fields-missing.pl \
	tests/rwaggbagcat-fields-two-files.pl \
	tests/rwaggbagcat-fields-sipv4.pl \
	tests/rwaggbagcat-fields-sipv6.pl \
	tests/rwaggbagtool-null-input.pl \
	tests/rwaggbagtool-bad-scalar-multiply0.pl \
	tests/rwaggbagtool-bad-scalar-multiply-key.pl \
	tests/rwaggbagtool-bad-scalar-multiply-invalid.pl \
	tests/rwaggbagtool-bad-backup-no-inplace.pl \
	tests/rwaggbagtool-bad-inplace-devnull.pl \
	tests/rwaggbagtool-ports-proto-remove.pl \
	tests/rwaggbagtool-ports-proto-select.pl \
	tests/rwaggbagtool-to-ipset-sipv4.pl \
	tests/rwaggbagtool-to-ipset-dipv6.pl \
	tests/rwaggbagtool-to-bag-sport-byte.pl \
	tests/rwaggbagtool-add-bags.pl \
	tests/rwaggbagtool-subtract-bags.pl \
	tests/rwaggbagtool-sip-dip-select-insert.pl \
	tests/rwaggbagtool-sip-dip-remove-insert.pl \
	tests/rwaggbagtool-subtract-self-aggbag.pl \
	tests/rwaggbagtool-subtract-self-to-bag.pl \
	tests/rwaggbagtool-subtract-self-to-ipset.pl \
	tests/rwaggbagtool-min-max-empty.pl \
	tests/rwaggbagtool-min-sport-1024.pl \
	tests/rwaggbagtool-max-ports-1024.pl \
	tests/rwaggbagtool-min-bytes-100000.pl \
	tests/rwaggbagtool-sip-intersect-10.pl \
	tests/rwaggbagtool-dip-complement-10.pl \
	tests/rwaggbagtool-scalar-multiply-all.pl \
	tests/rwaggbagtool-scalar-multiply-field.pl \
	tests/rwaggbagtool-scalar-multiply-overflow.pl \
	tests/rwaggbagtool-scalar-multiply-overflow2.pl \
	tests/rwaggbagtool-scalar-multiply-multiple.pl \
	tests/rwaggbagtool-divide.pl \
	tests/rwaggbagtool-multiply-divide.pl \
	tests/rwaggbagtool-divide-zero.pl \
	tests/rwaggbagtool-country-code-sip-filter.pl \
	tests/rwaggbagtool-country-code-dip.pl \
	tests/rwaggbagtool-country-code-sip-v4v6.pl \
	tests/rwaggbagtool-inplace-stdout.pl \
	tests/rwaggbagtool-inplace-noexist.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwaggbagtool-inplace-no-backup.pl \
	tests/rwaggbagtool-inplace-backup.pl \
	tests/rwaggbagtool-inplace-cleanup.pl \
	tests/rwaggbagtool-inplace-keep-temp.pl \
	tests/rwaggbagtool-notes.pl
