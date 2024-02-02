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

bin_PROGRAMS = mapsid rwsiteinfo

EXTRA_DIST = mapsid.pod rwsiteinfo.pod
if HAVE_POD2MAN
man1_MANS = mapsid.1 rwsiteinfo.1
endif


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

mapsid_SOURCES = mapsid.c

rwsiteinfo_SOURCES = rwsiteinfo.c


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS)
EXTRA_DIST += \
	tests/rwsiteinfo-site.conf \
	tests/at-class.txt \
	tests/at-flowtype.txt \
	tests/at-no-recurse.txt \
	tests/at-odd,n@me.txt \
	tests/at-sensor-bad.txt \
	tests/at-sensor.txt \
	tests/at-type.txt

TESTS = \
	tests/mapsid-help.pl \
	tests/mapsid-version.pl \
	tests/mapsid-lone-command.pl \
	tests/mapsid-classes.pl \
	tests/mapsid-by-name-or-id.pl \
	tests/mapsid-no-such-name.pl \
	tests/mapsid-no-such-id.pl \
	tests/mapsid-bad-id.pl \
	tests/rwsiteinfo-help.pl \
	tests/rwsiteinfo-version.pl \
	tests/rwsiteinfo-lone-command.pl \
	tests/rwsiteinfo-sensors.pl \
	tests/rwsiteinfo-classes.pl \
	tests/rwsiteinfo-types.pl \
	tests/rwsiteinfo-flowtypes.pl \
	tests/rwsiteinfo-class-types.pl \
	tests/rwsiteinfo-class-sensor.pl \
	tests/rwsiteinfo-sensor-class.pl \
	tests/rwsiteinfo-flowtype-sensor.pl \
	tests/rwsiteinfo-default-type.pl \
	tests/rwsiteinfo-type-default-type.pl \
	tests/rwsiteinfo-class-default-type.pl \
	tests/rwsiteinfo-default-class.pl \
	tests/rwsiteinfo-default-class-type.pl \
	tests/rwsiteinfo-class-default-class.pl \
	tests/rwsiteinfo-sensor-group.pl \
	tests/rwsiteinfo-all-fields.pl \
	tests/rwsiteinfo-limit-classes.pl \
	tests/rwsiteinfo-limit-sensors.pl \
	tests/rwsiteinfo-limit-sensor-group.pl \
	tests/rwsiteinfo-limit-groups.pl \
	tests/rwsiteinfo-limit-types.pl \
	tests/rwsiteinfo-limit-flowtypes.pl \
	tests/rwsiteinfo-raw-lists.pl \
	tests/rwsiteinfo-no-title-no-final-no-columns.pl \
	tests/rwsiteinfo-separators.pl \
	tests/rwsiteinfo-delimited.pl \
	tests/rwsiteinfo-long-name.pl \
	tests/rwsiteinfo-at-sensor.pl \
	tests/rwsiteinfo-at-type.pl \
	tests/rwsiteinfo-at-class.pl \
	tests/rwsiteinfo-at-flowtype.pl \
	tests/rwsiteinfo-at-odd-name.pl \
	tests/rwsiteinfo-at-no-recurse.pl \
	tests/rwsiteinfo-at-sensor-bad.pl \
	tests/rwsiteinfo-at-no-file.pl \
	tests/rwsiteinfo-at-bad-escape.pl \
	tests/rwsiteinfo-at-trailing-at.pl \
	tests/rwsiteinfo-at-long-path.pl
