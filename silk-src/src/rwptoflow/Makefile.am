## Copyright (C) 2005-2023 by Carnegie Mellon University.
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

bin_PROGRAMS = rwpdedupe rwpmatch rwptoflow
if HAVE_PYTHONBIN
bin_SCRIPTS = rwpcut
endif

noinst_LTLIBRARIES = rwp2f_minbytes.la

EXTRA_DIST = rwptoflow.pod rwpmatch.pod rwpdedupe.pod rwpcut.pod
if HAVE_POD2MAN
man1_MANS = rwptoflow.1 rwpmatch.1 rwpdedupe.1
if HAVE_PYTHONBIN
man1_MANS += rwpcut.1
endif
endif


# Additional Targets

EXTRA_PROGRAMS = rwpgenoffsetdata
# $(EXTRA_PROGRAMS) only need to appear in one of bin_PROGRAMS,
# noinst_PROGRAMS, or check_PROGRAMS
#check_PROGRAMS = $(EXTRA_PROGRAMS)
# Swap the comment character between bin_PROGRAMS and noinst_PROGRAMS
# to determine whether to install the test programs in $(bindir)
#bin_PROGRAMS += $(EXTRA_PROGRAMS)
noinst_PROGRAMS = $(EXTRA_PROGRAMS)


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS) $(STATIC_APPLICATIONS)
LDADD = ../libsilk/libsilk.la $(PCAP_LDFLAGS)

EXTRA_DIST += rwpcut.in rwpcut24.in

if HAVE_PYTHON24
rwpcut_tmpl = rwpcut24.in

MAKE_RWPCUT24 = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$(rwpcut_tmpl) || srcdir=$(srcdir)/ ; \
  $(make_python_script_edit) $${srcdir}$(rwpcut_tmpl) >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

rwpcut: Makefile $(rwpcut_tmpl)
	$(MAKE_RWPCUT24)

else

rwpcut: Makefile rwpcut.in
	$(MAKE_PYTHON_SCRIPT)

endif

MOSTLYCLEANFILES = rwpcut.tmp
CLEANFILES = rwpcut

rwp2f_minbytes_la_SOURCES = rwp2f_minbytes.c rwppacketheaders.h
rwp2f_minbytes_la_LDFLAGS = -module $(SILK_PLUGIN_LIBTOOL_FLAGS)

rwpdedupe_SOURCES = rwpdedupe.c rwppacketheaders.h

rwpgenoffsetdata_SOURCES = rwpgenoffsetdata.c rwppacketheaders.h

rwpmatch_SOURCES = rwpmatch.c rwppacketheaders.h

rwptoflow_SOURCES = rwptoflow.c rwppacketheaders.h
rwptoflow_LDADD = $(LDADD)


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk
