## Copyright (C) 2011-2023 by Carnegie Mellon University.
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

bin_PROGRAMS = rwrecgenerator

EXTRA_DIST = rwrecgenerator.pod
if HAVE_POD2MAN
man1_MANS = rwrecgenerator.1
endif

EXTRA_PROGRAMS = rwrecgenerator-threaded skheap-rwrec-test


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwrecgenerator_SOURCES = rwrecgenerator.c \
	 skheap-rwrec.c skheap-rwrec.h \
	 stream-cache.c stream-cache.h

# The code in the threaded version is outdated.  It is also slower
# than the non-threaded version.
rwrecgenerator_threaded_SOURCES =  rwrecgenerator-threaded.c \
	 skheap-rwrec.c skheap-rwrec.h \
	 stream-cache.c stream-cache.h
rwrecgenerator_threaded_LDADD = ../libsilk/libsilk-thrd.la \
	 $(LDADD) $(PTHREAD_LDFLAGS)

skheap_rwrec_test_SOURCES = skheap-rwrec-test.c \
	 skheap-rwrec.c skheap-rwrec.h


# this example file can be used to build a prefix map to pass to
# rwrecgenerator's --sensor-prefix-map switch
EXTRA_DIST += sensor-map.txt

CLEANFILES = $(EXTRA_PROGRAMS)

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/rwrecgenerator-help.pl \
	tests/rwrecgenerator-version.pl \
	tests/rwrecgenerator-lone-command.pl \
	tests/rwrecgenerator-null-input.pl \
	tests/rwrecgenerator-text-output.pl \
	tests/rwrecgenerator-binary-output.pl
