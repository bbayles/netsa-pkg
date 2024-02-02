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
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $");

# Installed Targets

bin_PROGRAMS = rwgeoip2ccmap rwip2cc rwpmapbuild rwpmapcat rwpmaplookup

EXTRA_DIST = addrtype.pod ccfilter.pod pmapfilter.pod rwgeoip2ccmap.pod \
	rwip2cc.pod rwpmapbuild.pod rwpmapcat.pod rwpmaplookup.pod
if HAVE_POD2MAN
man1_MANS = rwgeoip2ccmap.1 rwip2cc.1 rwpmapbuild.1 rwpmapcat.1 rwpmaplookup.1
man3_MANS = addrtype.3 ccfilter.3 pmapfilter.3
endif

dist_pkgdata_DATA = addrtype-templ.txt


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS) $(LIBMAXMINDDB_CFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la

rwgeoip2ccmap_SOURCES = rwgeoip2ccmap.l
rwgeoip2ccmap_LDADD = $(LDADD) $(LIBMAXMINDDB_LDFLAGS)

rwip2cc_SOURCES = rwip2cc.c

rwpmapbuild_SOURCES = rwpmapbuild.l

rwpmapcat_SOURCES = rwpmapcat.c

rwpmaplookup_SOURCES = rwpmaplookup.c


# add switches to flex that remove unused functions
AM_LFLAGS = $(FLEX_NOFUNS)

# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# Tests

# Required files; variables defined in ../../build.mk
check_DATA = $(SILK_TESTSDIR) $(SILK_TESTDATA)

EXTRA_DIST += $(TESTS) \
	tests/GeoLite2-Country-Blocks-IPv4.csv \
	tests/GeoLite2-Country-Blocks-IPv6.csv \
	tests/GeoLite2-Country-Locations-en.csv

TESTS = \
	tests/rwip2cc-help.pl \
	tests/rwip2cc-version.pl \
	tests/rwip2cc-lone-command.pl \
	tests/rwip2cc-null-input.pl \
	tests/rwgeoip2ccmap-help.pl \
	tests/rwgeoip2ccmap-version.pl \
	tests/rwgeoip2ccmap-lone-command.pl \
	tests/rwgeoip2ccmap-null-input.pl \
	tests/rwpmapbuild-help.pl \
	tests/rwpmapbuild-version.pl \
	tests/rwpmapbuild-lone-command.pl \
	tests/rwpmapbuild-null-input.pl \
	tests/rwpmapcat-help.pl \
	tests/rwpmapcat-version.pl \
	tests/rwpmapcat-lone-command.pl \
	tests/rwpmapcat-null-input.pl \
	tests/rwpmaplookup-help.pl \
	tests/rwpmaplookup-version.pl \
	tests/rwpmaplookup-lone-command.pl \
	tests/rwpmaplookup-null-input.pl \
	tests/rwip2cc-address.pl \
	tests/rwip2cc-address-print-0.pl \
	tests/rwip2cc-address-print-1.pl \
	tests/rwip2cc-stdin.pl \
	tests/rwip2cc-stdin-print-1.pl \
	tests/rwip2cc-stdin-print-0.pl \
	tests/rwip2cc-stdin-no-columns.pl \
	tests/rwip2cc-stdin-delimited.pl \
	tests/rwip2cc-stdin-integer-ips.pl \
	tests/rwip2cc-stdin-zero-pad.pl \
	tests/rwip2cc-stdin-environ.pl \
	tests/rwip2cc-many-ips.pl \
	tests/rwgeoip2ccmap-legacy-csv-v4.pl \
	tests/rwgeoip2ccmap-legacy-csv-v6.pl \
	tests/rwgeoip2ccmap-legacy-csv-combo.pl \
	tests/rwgeoip2ccmap-geo2-csv.pl \
	tests/rwpmapcat-ip.pl \
	tests/rwpmapcat-ip-no-cidr.pl \
	tests/rwpmapcat-ip-integer-ips.pl \
	tests/rwpmapcat-ip-zero-pad.pl \
	tests/rwpmapcat-ip-delimited.pl \
	tests/rwpmapcat-ip-label.pl \
	tests/rwpmapcat-ip-mapname.pl \
	tests/rwpmapcat-ip-type.pl \
	tests/rwpmapcat-ip-ignore-label.pl \
	tests/rwpmapcat-ip-ignore-ip.pl \
	tests/rwpmapcat-ip-left-just.pl \
	tests/rwpmapcat-ip-v6.pl \
	tests/rwpmapcat-ip-no-cidr-v6.pl \
	tests/rwpmapcat-ip-ignore-ip-v6.pl \
	tests/rwpmapcat-proto-port.pl \
	tests/rwpmapcat-proto-port-no-title.pl \
	tests/rwpmapcat-proto-port-label.pl \
	tests/rwpmapcat-proto-port-mapname.pl \
	tests/rwpmapcat-proto-port-type.pl \
	tests/rwpmapcat-proto-port-ignore.pl \
	tests/rwpmapcat-stdin.pl \
	tests/rwpmapcat-stdin-map-file.pl \
	tests/rwpmapcat-cc-integer.pl \
	tests/rwpmapcat-cc-v6-integer.pl \
	tests/rwpmapcat-cc.pl \
	tests/rwpmapcat-cc-v6.pl \
	tests/rwpmapcat-addrtype-env.pl \
	tests/rwpmapcat-addrtype.pl \
	tests/rwpmaplookup-value-address-type.pl \
	tests/rwpmaplookup-key-val-address-type.pl \
	tests/rwpmaplookup-stdin-address-type.pl \
	tests/rwpmaplookup-ipset-address-type.pl \
	tests/rwpmaplookup-value-country-code.pl \
	tests/rwpmaplookup-key-val-country-code.pl \
	tests/rwpmaplookup-start-end-block-country-code.pl \
	tests/rwpmaplookup-block-country-code.pl \
	tests/rwpmaplookup-stdin-country-code.pl \
	tests/rwpmaplookup-ipset-country-code.pl \
	tests/rwpmaplookup-value-country-code-v6.pl \
	tests/rwpmaplookup-key-val-country-code-v6.pl \
	tests/rwpmaplookup-stdin-country-code-v6.pl \
	tests/rwpmaplookup-ipset-country-code-v6.pl \
	tests/rwpmaplookup-value-ip-v4.pl \
	tests/rwpmaplookup-key-val-ip-v4.pl \
	tests/rwpmaplookup-start-end-block-ip-v4.pl \
	tests/rwpmaplookup-block-ip-v4.pl \
	tests/rwpmaplookup-stdin-ip-v4.pl \
	tests/rwpmaplookup-ipset-ip-v4.pl \
	tests/rwpmaplookup-value-ip-v6.pl \
	tests/rwpmaplookup-key-val-ip-v6.pl \
	tests/rwpmaplookup-start-end-block-ip-v6.pl \
	tests/rwpmaplookup-block-ip-v6.pl \
	tests/rwpmaplookup-stdin-ip-v6.pl \
	tests/rwpmaplookup-ipset-ip-v6.pl \
	tests/rwpmaplookup-value-proto-port.pl \
	tests/rwpmaplookup-key-val-proto-port.pl \
	tests/rwpmaplookup-start-end-block-proto-port.pl \
	tests/rwpmaplookup-block-proto-port.pl \
	tests/rwpmaplookup-files-proto-port.pl
