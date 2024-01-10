## Copyright (C) 2007-2023 by Carnegie Mellon University.
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
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $")

# Installed Targets

# A static "convenience" library to support PySiLK Plugins
noinst_LTLIBRARIES = libsilkpython.la

# Python extension (this is loaded by the Python binary)
pkgpython_LTLIBRARIES = pysilk.la

# Python files to install
pkgpython_PYTHON = python/__init__.py python/fglob.py \
		   python/plugin.py python/site.py 

# netsa-silk compatibility layer
pkgpython_PYTHON += python/_netsa_silk.py
python_PYTHON     = python/netsa_silk.py


# Manual pages
EXTRA_DIST = pysilk.pod silkpython.pod
if HAVE_POD2MAN
man3_MANS = pysilk.3 silkpython.3
endif

# Additional Targets

PYSILK_TEST = pysilk_test.py
PYSILK_TEST_SRC = python/$(PYSILK_TEST).in
EXTRA_DIST += $(PYSILK_TEST_SRC)
noinst_SCRIPTS = $(PYSILK_TEST)


# Build Rules

AM_CPPFLAGS = $(SK_SRC_INCLUDES) $(PYTHON_CPPFLAGS) $(SK_CPPFLAGS)
AM_CFLAGS = $(WARN_CFLAGS) $(SK_CFLAGS)
AM_LDFLAGS = $(SK_LDFLAGS)

# The Python extension.  This extension gets loaded by a stand-alone
# Python invocation, so it must pull in the libsilk references.
pysilk_la_SOURCES     = pysilk.c pysilk_common.c pysilk_common.h
pysilk_la_LDFLAGS     = -module -avoid-version -shrext $(PYTHON_SO_EXTENSION) \
                        -rpath '$(pkgpythondir)' \
                        $(AM_LDFLAGS)
pysilk_la_LIBADD      = ../libsilk/libsilk.la

# The static library loaded as "plug-in" by rwfilter, rwcut, ...
libsilkpython_la_SOURCES = silkpython.c pysilk_common.c pysilk_common.h pysilk.c
libsilkpython_la_LIBADD  =
libsilkpython_la_LDFLAGS = 

MAKE_PYSILK_TEST = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f './$(PYSILK_TEST_SRC)' || srcdir='$(srcdir)/' ; \
  sed \
    -e 's|@PYTHON[@]|$(PYTHON)|g' \
    "$${srcdir}$(PYSILK_TEST_SRC)" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

$(PYSILK_TEST): Makefile $(PYSILK_TEST_SRC)
	$(MAKE_PYSILK_TEST)

CLEANFILES = $(noinst_SCRIPTS)


# Global Rules
include $(top_srcdir)/build.mk
include $(top_srcdir)/lib-deps.mk


# "make check" in the tests directory will make this target with
# MINI_INST_DIR set to the location to install pysilk
#
# Note: we cannot install pysilk.la this way, since it must know the
# location of libsilk
pysilk_mini_install_dir = $(top_builddir)/tests/silk
pysilk_mini_install = $(pysilk_mini_install_dir)/pysilk-mini-install

pysilk-mini-install: $(pysilk_mini_install)

$(pysilk_mini_install): $(pkgpython_PYTHON)
	test -d $(pysilk_mini_install_dir)
	@MINI_INST_DIR=`cd '$(pysilk_mini_install_dir)' && pwd` ; \
	  echo $(MAKE) do-pysilk-mini-install MINI_INST_DIR="$$MINI_INST_DIR" ; \
	  $(MAKE) do-pysilk-mini-install MINI_INST_DIR="$$MINI_INST_DIR"
	date > $@

do-pysilk-mini-install:
	test -n '$(MINI_INST_DIR)' && test -d '$(MINI_INST_DIR)'
	@list="$(pkgpython_PYTHON)" ; \
	for p in $$list ; do \
	    f=`basename $$p` ; \
	    test -f "$(MINI_INST_DIR)/$$f" && rm -f "$(MINI_INST_DIR)/$$f" ; \
	    d='' ; \
	    test -f "./$$p" || d='$(srcdir)/' ; \
	    echo cp "$$d$$p" "$(MINI_INST_DIR)/$$f" ; \
	    cp "$$d$$p" "$(MINI_INST_DIR)/$$f" ; \
	done

.PHONY: pysilk-mini-install do-pysilk-mini-install
