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
## RCSIDENT("$SiLK: Makefile.am 951115b8bda0 2023-09-14 21:36:15Z mthomas $");

# Installed Targets

bin_PROGRAMS = silk_config

lib_LTLIBRARIES = libsilk.la libsilk-thrd.la
libsilk_version = 29:0:1
# At previous release: libsilk_version = 29:0:1

libsilk_thrd_version = 6:6:1
# At previous release: libsilk_thrd_version = 6:6:1


EXTRA_DIST = silk_config.pod silk.conf.pod silk.pod
if HAVE_POD2MAN
man1_MANS = silk_config.1
man5_MANS = silk.conf.5
man7_MANS = silk.7
endif

pkginclude_HEADERS = hashlib.h iptree.h rwascii.h rwrec.h silk.h	\
	 silk_files.h silk_types.h skaggbag.h skbag.h skcountry.h	\
	 skdaemon.h skdeque.h skdllist.h skheader.h skheap.h skipaddr.h \
	 skipset.h sklog.h skmempool.h sknetstruct.h skplugin.h		\
	 skpolldir.h skprefixmap.h sksite.h skstream.h skstringmap.h	\
	 sktempfile.h skthread.h sktimer.h sktracemsg.h skvector.h	\
	 utils.h			 				\
	 redblack/redblack.h $(LEGACY_HDRS) $(EXTRA_HDRS)

LEGACY_HDRS = bagtree.h rwpack.h

if NEED_GETOPT_LONG_ONLY
EXTRA_HDRS = gnu_getopt.h
endif

dist_pkgdata_DATA = silk.magic


# Additional Targets

EXTRA_PROGRAMS = hashlib_metrics hashlib_tests \
	 options-parse-test parse-tests rwreadonly \
	 skbitmap-test skheader-test skheap-test skiobuf-test \
	 skmempool-test skprefixmap-test sksiteconfig-test \
	 skstream-test skstringmap-test skvector-test \
	 skdeque-test sklog-test skpolldir-test sktimer-test
# $(EXTRA_PROGRAMS) only need to appear in one of bin_PROGRAMS,
# noinst_PROGRAMS, or check_PROGRAMS
#check_PROGRAMS = $(EXTRA_PROGRAMS)
# Swap the comment character between bin_PROGRAMS and noinst_PROGRAMS
# to determine whether to install the test programs in $(bindir)
#bin_PROGRAMS += $(EXTRA_PROGRAMS)
noinst_PROGRAMS = $(EXTRA_PROGRAMS)


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS) \
    -DSILK_DATA_ROOTDIR='"${SILK_DATA_ROOTDIR}"' \
    -DSILK_PYTHON_SITE_PKG='"${PYTHON_SITE_PKG}"'
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)

# Sources are maintained in a separate file
include Makefile-sources
EXTRA_DIST += getopt.c hashlib-lookup2.c hashlib-lookup3.c \
	 iptree.c

libsilk_la_SOURCES = $(SOURCES_LIBSILK)
libsilk_la_LDFLAGS = -version-info $(libsilk_version)

libsilk_thrd_la_SOURCES = $(SOURCES_LIBSILK_THRD)
libsilk_thrd_la_LDFLAGS = -version-info $(libsilk_thrd_version)

nodist_silk_config_SOURCES = silk_config.c
silk_config_CPPFLAGS = -DINCLUDEDIR='"$(includedir)"' -DLIBDIR='"$(libdir)"' $(AM_CPPFLAGS)
silk_config_LDADD = libsilk.la

# Output of hashlib_metrics depends on whether HASHLIB_RECORD_STATS
# was defined when hashlib.c and hashlib_metrics.c were compiled.
# Output includes timing info, so not good for "make check" test.
hashlib_metrics_SOURCES = hashlib_metrics.c
hashlib_metrics_LDADD = libsilk.la

hashlib_tests_SOURCES = hashlib_tests.c
hashlib_tests_LDADD = libsilk.la

options_parse_test_SOURCES = options-parse-test.c 
options_parse_test_LDADD = libsilk.la

parse_tests_SOURCES = parse-tests.c
parse_tests_LDADD = libsilk.la

rwreadonly_SOURCES = rwreadonly.c
rwreadonly_LDADD = libsilk.la

skbitmap_test_SOURCES = skbitmap-test.c
skbitmap_test_LDADD = libsilk.la

skheader_test_SOURCES = skheader-test.c
skheader_test_LDADD = libsilk.la

skheap_test_SOURCES = skheap-test.c
skheap_test_LDADD = libsilk.la

skmempool_test_SOURCES = skmempool-test.c
skmempool_test_LDADD = libsilk.la

skiobuf_test_SOURCES = skiobuf-test.c
skiobuf_test_LDADD = libsilk.la

skprefixmap_test_SOURCES = skprefixmap-test.c
skprefixmap_test_LDADD = libsilk.la

sksiteconfig_test_SOURCES = sksiteconfig-test.c sksiteconfig.h
sksiteconfig_test_LDADD = libsilk.la

skstream_test_SOURCES = skstream-test.c
skstream_test_LDADD = libsilk.la

skstringmap_test_SOURCES = skstringmap-test.c
skstringmap_test_LDADD = libsilk.la

skvector_test_SOURCES = skvector-test.c
skvector_test_LDADD = libsilk.la

skdeque_test_SOURCES = skdeque-test.c
skdeque_test_LDADD   = libsilk-thrd.la libsilk.la $(PTHREAD_LDFLAGS)

sklog_test_SOURCES = sklog-test.c
sklog_test_LDADD   = libsilk-thrd.la libsilk.la $(PTHREAD_LDFLAGS)

skpolldir_test_SOURCES = skpolldir-test.c
skpolldir_test_LDADD   = libsilk-thrd.la libsilk.la $(PTHREAD_LDFLAGS)

sktimer_test_SOURCES = sktimer-test.c
sktimer_test_LDADD   = libsilk-thrd.la libsilk.la $(PTHREAD_LDFLAGS)

# add switches to flex that remove unused functions
AM_LFLAGS = $(FLEX_NOFUNS)

AM_YFLAGS = -d
sksiteconfig_lex.$(OBJEXT) sksiteconfig_lex.lo: sksiteconfig_parse.h

# Include the redblack docs in the distribution
EXTRA_DIST += redblack/AUTHORS redblack/COPYING




# Global Rules
include $(top_srcdir)/build.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR)

EXTRA_DIST += $(TESTS)

TESTS = \
	tests/run-hashlib-tests.pl \
	tests/run-skheap-test.pl \
	tests/run-skmempool-test.pl \
	tests/run-skiobuf-test.pl \
	tests/run-skdeque-test.pl \
	tests/run-skstringmap-test.pl \
	tests/run-skvector-test.pl \
	tests/run-parse-tests-numbers.pl \
	tests/run-parse-tests-lists.pl \
	tests/run-parse-tests-dates.pl \
	tests/run-parse-tests-tcp-flags.pl \
	tests/run-parse-tests-signals.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/run-parse-tests-ip-addresses.pl \
	tests/run-parse-tests-host-port-pairs.pl \
	tests/run-skbitmap-test.pl
