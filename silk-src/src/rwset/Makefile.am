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

bin_PROGRAMS = rwset rwsetbuild rwsetcat rwsetmember rwsettool

EXTRA_DIST = rwset.pod rwsetbuild.pod rwsetcat.pod rwsetmember.pod \
	 rwsettool.pod
if HAVE_POD2MAN
man1_MANS = rwset.1 rwsetbuild.1 rwsetcat.1 rwsetmember.1 \
	 rwsettool.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwset_SOURCES = rwset.c

rwsetbuild_SOURCES = rwsetbuild.c

rwsetcat_SOURCES = rwsetcat.c

rwsetmember_SOURCES = rwsetmember.c

rwsettool_SOURCES = rwsettool.c

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


CLEANFILES = rwsetunion.1 rwsetintersect.1 rwsetunion rwsetintersect

# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA) $(SILK_TESTSETS)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwset-help.pl \
	tests/rwset-version.pl \
	tests/rwset-lone-command.pl \
	tests/rwsetbuild-help.pl \
	tests/rwsetbuild-version.pl \
	tests/rwsetbuild-lone-command.pl \
	tests/rwsetcat-help.pl \
	tests/rwsetcat-version.pl \
	tests/rwsetcat-lone-command.pl \
	tests/rwsettool-help.pl \
	tests/rwsettool-version.pl \
	tests/rwsettool-lone-command.pl \
	tests/rwsetmember-help.pl \
	tests/rwsetmember-version.pl \
	tests/rwsetmember-lone-command.pl \
	tests/rwset-no-switches.pl \
	tests/rwset-no-files.pl \
	tests/rwset-null-input.pl \
	tests/rwset-empty-input.pl \
	tests/rwset-sip.pl \
	tests/rwset-dip.pl \
	tests/rwset-nhip.pl \
	tests/rwset-sip-dip-1.pl \
	tests/rwset-sip-dip-2.pl \
	tests/rwset-multiple-inputs.pl \
	tests/rwset-stdin.pl \
	tests/rwset-copy-input.pl \
	tests/rwset-sip-v6.pl \
	tests/rwset-dip-v6.pl \
	tests/rwset-nhip-v6.pl \
	tests/rwset-sip-dip-1-v6.pl \
	tests/rwset-sip-dip-2-v6.pl \
	tests/rwsetcat-null-input.pl \
	tests/rwsetcat-count-ips.pl \
	tests/rwsetcat-cidr-blocks.pl \
	tests/rwsetcat-ip-ranges.pl \
	tests/rwsetcat-integer-ips.pl \
	tests/rwsetcat-hexadecimal-ips.pl \
	tests/rwsetcat-zero-pad-ips.pl \
	tests/rwsetcat-net-struct.pl \
	tests/rwsetcat-net-struct-ATS.pl \
	tests/rwsetcat-net-struct-12.pl \
	tests/rwsetcat-cidr-blocks-s1-v4.pl \
	tests/rwsetcat-cidr-blocks-s2-v4.pl \
	tests/rwsetcat-count-ips-s1-v4.pl \
	tests/rwsetcat-count-ips-s2-v4.pl \
	tests/rwsetcat-count-ips-filename-s1-v4.pl \
	tests/rwsetcat-count-ips-s1-s2-v4.pl \
	tests/rwsetcat-count-ips-filename-s1-s2-v4.pl \
	tests/rwsetcat-ip-ranges-s1-v4.pl \
	tests/rwsetcat-ip-ranges-filename-s1-v4.pl \
	tests/rwsetcat-ip-ranges-s2-v4.pl \
	tests/rwsetcat-net-struct-s1-v4.pl \
	tests/rwsetcat-net-struct-s2-v4.pl \
	tests/rwsetcat-net-struct-18-s1-v4.pl \
	tests/rwsetcat-net-struct-20-s2-v4.pl \
	tests/rwsetcat-net-struct-empty-v4.pl \
	tests/rwsetcat-net-struct-10-10-v4.pl \
	tests/rwsetcat-net-struct-10-7-v4.pl \
	tests/rwsetcat-net-struct-v6.pl \
	tests/rwsetcat-net-struct-48-v6.pl \
	tests/rwsetcat-net-struct-60.pl \
	tests/rwsetcat-no-cidr-s2-v6.pl \
	tests/rwsetcat-cidr-blocks-s1-v6.pl \
	tests/rwsetcat-cidr-blocks-s2-v6.pl \
	tests/rwsetcat-count-ips-s1-v6.pl \
	tests/rwsetcat-count-ips-s2-v6.pl \
	tests/rwsetcat-ip-ranges-s1-v6.pl \
	tests/rwsetcat-ip-ranges-s2-v6.pl \
	tests/rwsetcat-net-struct-s1-v6.pl \
	tests/rwsetcat-net-struct-s2-v6.pl \
	tests/rwsetcat-net-struct-s1-58-v6.pl \
	tests/rwsetcat-net-struct-s2-60-v6.pl \
	tests/rwsetcat-net-struct-s3-v4-s3-v6.pl \
	tests/rwsetcat-net-struct-empty-v6.pl \
	tests/rwsetcat-net-struct-2001-db8-34-v6.pl \
	tests/rwsetcat-net-struct-2001-db8-31-v6.pl \
	tests/rwsettool-null-input.pl \
	tests/rwsettool-output-path.pl \
	tests/rwsettool-sample-none.pl \
	tests/rwsettool-backup-no-inplace.pl \
	tests/rwsettool-inplace-devnull.pl \
	tests/rwsettool-union-s1-s2-v4.pl \
	tests/rwsettool-union-s2-s1-v4.pl \
	tests/rwsettool-intersect-s1-s2-v4.pl \
	tests/rwsettool-intersect-s2-s1-v4.pl \
	tests/rwsettool-difference-s1-s2-v4.pl \
	tests/rwsettool-difference-s2-s1-v4.pl \
	tests/rwsettool-symmet-diff-s1-s2-v4.pl \
	tests/rwsettool-symmet-diff-s2-s1-v4.pl \
	tests/rwsettool-union-s3-s4-v4.pl \
	tests/rwsettool-union-s4-s3-v4.pl \
	tests/rwsettool-intersect-s3-s4-v4.pl \
	tests/rwsettool-intersect-s4-s3-v4.pl \
	tests/rwsettool-difference-s3-s4-v4.pl \
	tests/rwsettool-difference-s4-s3-v4.pl \
	tests/rwsettool-symmet-diff-s3-s4-v4.pl \
	tests/rwsettool-symmet-diff-s4-s3-v4.pl \
	tests/rwsettool-inplace-stdout.pl \
	tests/rwsettool-inplace-noexist.pl \
	tests/rwsettool-inplace-no-backup.pl \
	tests/rwsettool-inplace-backup.pl \
	tests/rwsettool-mask-12-s1-v4.pl \
	tests/rwsettool-mask-12-s2-v4.pl \
	tests/rwsettool-mask-13-s1-v4.pl \
	tests/rwsettool-mask-13-s2-v4.pl \
	tests/rwsettool-mask-14-s1-v4.pl \
	tests/rwsettool-mask-14-s2-v4.pl \
	tests/rwsettool-mask-15-s1-v4.pl \
	tests/rwsettool-mask-15-s2-v4.pl \
	tests/rwsettool-mask-16-s1-v4.pl \
	tests/rwsettool-mask-16-s2-v4.pl \
	tests/rwsettool-mask-17-s1-v4.pl \
	tests/rwsettool-mask-17-s2-v4.pl \
	tests/rwsettool-mask-18-s1-v4.pl \
	tests/rwsettool-mask-18-s2-v4.pl \
	tests/rwsettool-mask-19-s1-v4.pl \
	tests/rwsettool-mask-19-s2-v4.pl \
	tests/rwsettool-mask-20-s1-v4.pl \
	tests/rwsettool-mask-20-s2-v4.pl \
	tests/rwsettool-mask-21-s1-v4.pl \
	tests/rwsettool-mask-21-s2-v4.pl \
	tests/rwsettool-mask-22-s1-v4.pl \
	tests/rwsettool-mask-22-s2-v4.pl \
	tests/rwsettool-mask-23-s1-v4.pl \
	tests/rwsettool-mask-23-s2-v4.pl \
	tests/rwsettool-mask-24-s1-v4.pl \
	tests/rwsettool-mask-24-s2-v4.pl \
	tests/rwsettool-mask-25-s1-v4.pl \
	tests/rwsettool-mask-25-s2-v4.pl \
	tests/rwsettool-mask-26-s1-v4.pl \
	tests/rwsettool-mask-26-s2-v4.pl \
	tests/rwsettool-mask-27-s1-v4.pl \
	tests/rwsettool-mask-27-s2-v4.pl \
	tests/rwsettool-mask-28-s1-v4.pl \
	tests/rwsettool-mask-28-s2-v4.pl \
	tests/rwsettool-mask-29-s1-v4.pl \
	tests/rwsettool-mask-29-s2-v4.pl \
	tests/rwsettool-mask-30-s1-v4.pl \
	tests/rwsettool-mask-30-s2-v4.pl \
	tests/rwsettool-union-s1-s2-v6.pl \
	tests/rwsettool-union-s2-s1-v6.pl \
	tests/rwsettool-intersect-s1-s2-v6.pl \
	tests/rwsettool-intersect-s2-s1-v6.pl \
	tests/rwsettool-difference-s1-s2-v6.pl \
	tests/rwsettool-difference-s2-s1-v6.pl \
	tests/rwsettool-symmet-diff-s1-s2-v6.pl \
	tests/rwsettool-symmet-diff-s2-s1-v6.pl \
	tests/rwsettool-union-s3-s4-v6.pl \
	tests/rwsettool-union-s4-s3-v6.pl \
	tests/rwsettool-intersect-s3-s4-v6.pl \
	tests/rwsettool-intersect-s4-s3-v6.pl \
	tests/rwsettool-difference-s3-s4-v6.pl \
	tests/rwsettool-difference-s4-s3-v6.pl \
	tests/rwsettool-symmet-diff-s3-s4-v6.pl \
	tests/rwsettool-symmet-diff-s4-s3-v6.pl \
	tests/rwsettool-mask-52-s1-v6.pl \
	tests/rwsettool-mask-52-s2-v6.pl \
	tests/rwsettool-mask-53-s1-v6.pl \
	tests/rwsettool-mask-53-s2-v6.pl \
	tests/rwsettool-mask-54-s1-v6.pl \
	tests/rwsettool-mask-54-s2-v6.pl \
	tests/rwsettool-mask-55-s1-v6.pl \
	tests/rwsettool-mask-55-s2-v6.pl \
	tests/rwsettool-mask-56-s1-v6.pl \
	tests/rwsettool-mask-56-s2-v6.pl \
	tests/rwsettool-mask-57-s1-v6.pl \
	tests/rwsettool-mask-57-s2-v6.pl \
	tests/rwsettool-mask-58-s1-v6.pl \
	tests/rwsettool-mask-58-s2-v6.pl \
	tests/rwsettool-mask-59-s1-v6.pl \
	tests/rwsettool-mask-59-s2-v6.pl \
	tests/rwsettool-mask-60-s1-v6.pl \
	tests/rwsettool-mask-60-s2-v6.pl \
	tests/rwsettool-mask-61-s1-v6.pl \
	tests/rwsettool-mask-61-s2-v6.pl \
	tests/rwsettool-mask-62-s1-v6.pl \
	tests/rwsettool-mask-62-s2-v6.pl \
	tests/rwsettool-mask-63-s1-v6.pl \
	tests/rwsettool-mask-63-s2-v6.pl \
	tests/rwsettool-mask-64-s1-v6.pl \
	tests/rwsettool-mask-64-s2-v6.pl \
	tests/rwsettool-mask-65-s1-v6.pl \
	tests/rwsettool-mask-65-s2-v6.pl \
	tests/rwsettool-mask-66-s1-v6.pl \
	tests/rwsettool-mask-66-s2-v6.pl \
	tests/rwsettool-mask-67-s1-v6.pl \
	tests/rwsettool-mask-67-s2-v6.pl \
	tests/rwsettool-mask-68-s1-v6.pl \
	tests/rwsettool-mask-68-s2-v6.pl \
	tests/rwsettool-mask-69-s1-v6.pl \
	tests/rwsettool-mask-69-s2-v6.pl \
	tests/rwsettool-mask-70-s1-v6.pl \
	tests/rwsettool-mask-70-s2-v6.pl \
	tests/rwsetbuild-null-input.pl \
	tests/rwsetbuild-ips.pl \
	tests/rwsetbuild-cidr.pl \
	tests/rwsetbuild-ranges.pl \
	tests/rwsetbuild-ips-v6.pl \
	tests/rwsetbuild-ips-s1-v4.pl \
	tests/rwsetbuild-ips-s2-v4.pl \
	tests/rwsetbuild-cidr-s1-v4.pl \
	tests/rwsetbuild-cidr-s2-v4.pl \
	tests/rwsetbuild-ranges-s1-v4.pl \
	tests/rwsetbuild-ranges-s2-v4.pl \
	tests/rwsetbuild-cidr-s1-v6.pl \
	tests/rwsetbuild-cidr-s2-v6.pl \
	tests/rwsetbuild-ranges-s1-v6.pl \
	tests/rwsetbuild-ranges-s2-v6.pl \
	tests/rwsetmember-null-input.pl \
	tests/rwsetmember-empy-input.pl \
	tests/rwsetmember-print-sets.pl \
	tests/rwsetmember-count.pl \
	tests/rwsetmember-print-sets-v6.pl \
	tests/rwsetmember-count-v6.pl \
	tests/rwsetmember-count-8-s1-s2-v4.pl \
	tests/rwsetmember-count-25-s1-s2-v4.pl \
	tests/rwsetmember-count-48-s1-s2-v6.pl \
	tests/rwsetmember-count-65-s1-s2-v6.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/rwsettool-union-data-v4.pl \
	tests/rwsettool-union-data-v6.pl \
	tests/rwsettool-union-data-v4v6.pl \
	tests/rwsettool-sample-ratio.pl \
	tests/rwsettool-sample-size.pl \
	tests/rwsettool-sample-ratio-v6.pl \
	tests/rwsettool-sample-size-v6.pl \
	tests/rwsettool-difference-ipv6.pl \
	tests/rwsettool-inplace-cleanup.pl \
	tests/rwsettool-inplace-keep-temp.pl \
	tests/rwsettool-notes.pl
