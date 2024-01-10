## Copyright (C) 2003-2023 by Carnegie Mellon University.
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

sbin_PROGRAMS = flowcap

EXTRA_DIST = flowcap.pod
if HAVE_POD2MAN
man8_MANS = flowcap.8
endif

conf_files = flowcap.conf
EXTRA_DIST += flowcap.conf.in

init_d_scripts = flowcap.init.d
EXTRA_DIST += flowcap.init.d.in


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(FIXBUF_CFLAGS) $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)

flowcap_SOURCES = flowcap.c flowcap.h flowcapsetup.c
flowcap_LDADD = ../libflowsource/libflowsource.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(FIXBUF_LDFLAGS) $(PTHREAD_LDFLAGS)


flowcap.conf: Makefile flowcap.conf.in
	$(MAKE_CONF_FILE)
flowcap.init.d: Makefile flowcap.init.d.in
	$(MAKE_INIT_D_SCRIPT)

all-local: $(conf_files) $(init_d_scripts)
install-data-local: install-conf-files install-init-d-scripts
uninstall-local: uninstall-conf-files uninstall-init-d-scripts

CLEANFILES = $(conf_files) $(init_d_scripts)

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)
EXTRA_DIST += tests/flowcap-daemon.py

MOSTLYCLEANFILES = tests/flowcap-daemon.pyc

TESTS = \
	tests/flowcap-help.pl \
	tests/flowcap-version.pl \
	tests/flowcap-lone-command.pl

# above tests are automatically generated;
# those below are written by hand
TESTS += \
	tests/flowcap-init-d.pl \
	tests/flowcap-netflowv5-v4.pl \
	tests/flowcap-netflowv5-any-v4.pl \
	tests/flowcap-netflowv5-v6.pl \
	tests/flowcap-ipfix-v4.pl \
	tests/flowcap-ipfix-any-v4.pl \
	tests/flowcap-ipfix-udp.pl \
	tests/flowcap-ipfix-v6.pl \
	tests/flowcap-ipfixv6-v6.pl
