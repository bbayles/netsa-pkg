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

bin_PROGRAMS = rwtotal

EXTRA_DIST = rwtotal.pod
if HAVE_POD2MAN
man1_MANS = rwtotal.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwtotal_SOURCES = rwtotal.c rwtotal.h rwtotalsetup.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwtotal-help.pl \
	tests/rwtotal-version.pl \
	tests/rwtotal-lone-command.pl \
	tests/rwtotal-no-switches.pl \
	tests/rwtotal-no-files.pl \
	tests/rwtotal-null-input.pl \
	tests/rwtotal-key-conflict.pl \
	tests/rwtotal-sip-f-8.pl \
	tests/rwtotal-sip-f-16.pl \
	tests/rwtotal-sip-f-24.pl \
	tests/rwtotal-sip-l-8.pl \
	tests/rwtotal-sip-l-16.pl \
	tests/rwtotal-dip-f-8.pl \
	tests/rwtotal-dip-f-16.pl \
	tests/rwtotal-dip-f-24.pl \
	tests/rwtotal-dip-l-8.pl \
	tests/rwtotal-dip-l-16.pl \
	tests/rwtotal-dport.pl \
	tests/rwtotal-proto.pl \
	tests/rwtotal-packets.pl \
	tests/rwtotal-bytes.pl \
	tests/rwtotal-duration.pl \
	tests/rwtotal-sport-mn-rec.pl \
	tests/rwtotal-sport-mn-pkt.pl \
	tests/rwtotal-sport-mn-byt.pl \
	tests/rwtotal-sport-mx-rec.pl \
	tests/rwtotal-sport-mx-pkt.pl \
	tests/rwtotal-sport-mx-byt.pl \
	tests/rwtotal-summation.pl \
	tests/rwtotal-no-title.pl \
	tests/rwtotal-no-column.pl \
	tests/rwtotal-delimited.pl \
	tests/rwtotal-empty-input.pl \
	tests/rwtotal-multiple-inputs.pl \
	tests/rwtotal-multiple-inputs-v6.pl \
	tests/rwtotal-multiple-inputs-v4v6.pl \
	tests/rwtotal-copy-input.pl \
	tests/rwtotal-stdin.pl \
	tests/rwtotal-icmp-code.pl
