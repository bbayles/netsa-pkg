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

pkglib_LTLIBRARIES = app-mismatch.la conficker-c.la cutmatch.la flowkey.la \
	 flowrate.la int-ext-fields.la

EXTRA_DIST = app-mismatch.pod conficker-c.pod cutmatch.pod flowkey.pod \
	 flowrate.pod int-ext-fields.pod silk-plugin.pod
if HAVE_POD2MAN
man3_MANS = app-mismatch.3 conficker-c.3 cutmatch.3 flowkey.3 \
	 flowrate.3 int-ext-fields.3 silk-plugin.3
endif

noinst_LTLIBRARIES = skplugin-test.la rwslammer.la rwsynackfin.la \
	 uniq-distproto.la

check_PROGRAMS =


# Flags used when building plug-ins to be installed.  (This variable
# must have some non-empty value when automake is run, so include the
# "-module" switch here.)
INSTALLED_PLUGIN_FLAGS = -module $(SILK_PLUGIN_LIBTOOL_FLAGS)

# For plug-ins that are "noinst" we need to specify an -rpath so that
# libtool will build the *.so file.
NOINST_PLUGIN_FLAGS = -module $(SILK_PLUGIN_LIBTOOL_FLAGS) -rpath $(pkglibdir)


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)

app_mismatch_la_SOURCES = app-mismatch.c
app_mismatch_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

conficker_c_la_SOURCES = conficker-c.c
conficker_c_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

cutmatch_la_SOURCES = cutmatch.c
cutmatch_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

flowkey_la_SOURCES = flowkey.c
flowkey_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

flowrate_la_SOURCES = flowrate.c
flowrate_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

int_ext_fields_la_SOURCES = int-ext-fields.c
int_ext_fields_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

uniq_distproto_la_SOURCES = uniq-distproto.c
uniq_distproto_la_LDFLAGS = $(INSTALLED_PLUGIN_FLAGS)

rwslammer_la_SOURCES = rwslammer.c
rwslammer_la_LDFLAGS = $(NOINST_PLUGIN_FLAGS)

rwsynackfin_la_SOURCES = rwsynackfin.c
rwsynackfin_la_LDFLAGS = $(NOINST_PLUGIN_FLAGS)

skplugin_test_la_SOURCES = skplugin-test.c
skplugin_test_la_LDFLAGS = $(NOINST_PLUGIN_FLAGS)



# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk
