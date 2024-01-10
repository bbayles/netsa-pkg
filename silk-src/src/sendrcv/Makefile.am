## Copyright (C) 2006-2023 by Carnegie Mellon University.
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

sbin_PROGRAMS = rwreceiver rwsender

EXTRA_DIST = rwreceiver.pod rwsender.pod
if HAVE_POD2MAN
man8_MANS = rwreceiver.8 rwsender.8 
endif

conf_files = rwreceiver.conf rwsender.conf
EXTRA_DIST += rwreceiver.conf.in rwsender.conf.in

init_d_scripts = rwreceiver.init.d rwsender.init.d
EXTRA_DIST += rwreceiver.init.d.in rwsender.init.d.in


# Additional Targets

EXTRA_PROGRAMS = skmsg-test
# $(EXTRA_PROGRAMS) only need to appear in one of bin_PROGRAMS,
# noinst_PROGRAMS, or check_PROGRAMS
#check_PROGRAMS = $(EXTRA_PROGRAMS)
# Swap the comment character between bin_PROGRAMS and noinst_PROGRAMS
# to determine whether to install the test programs in $(bindir)
#bin_PROGRAMS += $(EXTRA_PROGRAMS)
noinst_PROGRAMS = $(EXTRA_PROGRAMS)

noinst_LTLIBRARIES = libsendrcv.la


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(GNUTLS_CFLAGS) $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD =  libsendrcv.la \
	 ../libsilk/libsilk-thrd.la \
	 ../libsilk/libsilk.la \
	 $(GNUTLS_LDFLAGS) $(PTHREAD_LDFLAGS)

libsendrcv_la_SOURCES = skmsg.c skmsg.h intdict.c intdict.h \
			multiqueue.c multiqueue.h \
			rwtransfer.c rwtransfer.h libsendrcv.h

rwreceiver_SOURCES = rwreceiver.c 

rwsender_SOURCES = rwsender.c

skmsg_test_SOURCES = skmsg-test.c

rwreceiver.conf: Makefile rwreceiver.conf.in
	$(MAKE_CONF_FILE)
rwsender.conf: Makefile rwsender.conf.in
	$(MAKE_CONF_FILE)
rwreceiver.init.d: Makefile rwreceiver.init.d.in
	$(MAKE_INIT_D_SCRIPT)
rwsender.init.d: Makefile rwsender.init.d.in
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
check_DATA = $(SILK_TESTSDIR) $(SILK_SENDRCVDATA)

EXTRA_DIST += $(TESTS)
EXTRA_DIST += tests/sendrcv-one-daemon.pm
EXTRA_DIST += tests/gencerts.py tests/sendrcv_tests.py
EXTRA_DIST += tests/post-command.sh
EXTRA_DIST += \
	tests/ca-expired-cert.pem tests/ca-expired-key.pem \
	tests/ca_cert_key8.pem \
	tests/cert-key1-ca_cert_key8.p12 tests/cert-key2-ca_cert_key8.p12 \
	tests/cert-key3-ca_cert_key8.p12 tests/cert-key4-ca_cert_key8.p12 \
	tests/cert-key5-ca_cert_key8.p12 tests/cert-key6-ca_cert_key8.p12 \
	tests/cert-key7-ca_cert_key8.p12 \
	tests/expired-cert.pem tests/expired-key.pem \
	tests/key1.pem tests/key2.pem tests/key3.pem tests/key4.pem \
	tests/key5.pem tests/key6.pem tests/key7.pem tests/key8.pem \
	tests/other-ca-cert.pem tests/other-ca-key.pem \
	tests/other-cert.pem tests/other-key.pem \
	tests/signed-expired-ca-cert.pem tests/signed-expired-ca-key.pem

MOSTLYCLEANFILES = tests/gencerts.pyc tests/sendrcv_tests.pyc

AM_TESTS_ENVIRONMENT += \
	SILK_SENDRCVDATA=$(SILK_SENDRCVDATA) ; export SILK_SENDRCVDATA ;

TESTS = \
	tests/rwsender-help.pl \
	tests/rwsender-version.pl \
	tests/rwsender-lone-command.pl \
	tests/rwreceiver-help.pl \
	tests/rwreceiver-version.pl \
	tests/rwreceiver-lone-command.pl

# The following are generated by hand
TESTS += \
	tests/rwreceiver-init-d.pl \
	tests/rwsender-init-d.pl \
	tests/sendrcv-testConnectOnlyIPv4Addr.pl \
	tests/sendrcv-testConnectOnlyHostname.pl \
	tests/sendrcv-testConnectOnlyTLS.pl \
	tests/sendrcv-testConnectOnlyIPv6Addr.pl \
	tests/sendrcv-testExpiredCertificateTLS.pl \
	tests/sendrcv-testExpiredAuthorityTLS.pl \
	tests/sendrcv-testMismatchedCertsTLS.pl \
	tests/sendrcv-testOtherCertsTLS.pl \
	tests/sendrcv-testSendRcvStopReceiverServer.pl \
	tests/sendrcv-testSendRcvStopSenderServer.pl \
	tests/sendrcv-testSendRcvStopReceiverClient.pl \
	tests/sendrcv-testSendRcvStopSenderClient.pl \
	tests/sendrcv-testSendRcvKillReceiverServer.pl \
	tests/sendrcv-testSendRcvKillSenderServer.pl \
	tests/sendrcv-testSendRcvKillReceiverClient.pl \
	tests/sendrcv-testSendRcvKillSenderClient.pl \
	tests/sendrcv-testSendRcvStopReceiverServerTLS.pl \
	tests/sendrcv-testSendRcvStopSenderServerTLS.pl \
	tests/sendrcv-testSendRcvStopReceiverClientTLS.pl \
	tests/sendrcv-testSendRcvStopSenderClientTLS.pl \
	tests/sendrcv-testSendRcvKillReceiverServerTLS.pl \
	tests/sendrcv-testSendRcvKillSenderServerTLS.pl \
	tests/sendrcv-testSendRcvKillReceiverClientTLS.pl \
	tests/sendrcv-testSendRcvKillSenderClientTLS.pl \
	tests/sendrcv-testMultiple.pl \
	tests/sendrcv-testMultipleTLS.pl \
	tests/sendrcv-testFilter.pl \
	tests/sendrcv-testPostCommand.pl
