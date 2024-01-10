##  Copyright 2006-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (toplevel)
##  autotools build system for YAF
##  ------------------------------------------------------------------------
##  Authors: Brian Trammell
##  ------------------------------------------------------------------------
##  @DISTRIBUTION_STATEMENT_BEGIN@
##  YAF 2.15.0
##
##  Copyright 2023 Carnegie Mellon University.
##
##  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
##  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
##  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
##  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
##  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
##  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
##  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
##  INFRINGEMENT.
##
##  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
##  contact permission@sei.cmu.edu for full terms.
##
##  [DISTRIBUTION STATEMENT A] This material has been approved for public
##  release and unlimited distribution.  Please see Copyright notice for
##  non-US Government use and distribution.
##
##  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##  Contract No.: FA8702-15-D-0002
##  Contractor Name: Carnegie Mellon University
##  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
##  The Government's rights to use, modify, reproduce, release, perform,
##  display, or disclose this software are restricted by paragraph (b)(2) of
##  the Rights in Noncommercial Computer Software and Noncommercial Computer
##  Software Documentation clause contained in the above identified
##  contract. No restrictions apply after the expiration date shown
##  above. Any reproduction of the software or portions thereof marked with
##  this legend must also reproduce the markings.
##
##  This Software includes and/or makes use of Third-Party Software each
##  subject to its own license.
##
##  DM23-2313
##  @DISTRIBUTION_STATEMENT_END@
##  ------------------------------------------------------------------------


ACLOCAL_AMFLAGS = -I m4

# Avoid picking up MacOS X resource forks in "make dist"
am__tar = COPY_EXTENDED_ATTRIBUTES_DISABLE=1 COPYFILE_DISABLE=1 ${AMTAR} cof - "$$tardir"

SUBDIRS = libltdl
SUBDIRS += infomodel lua airframe src include etc scripts doc

include doxygen.am

MOSTLYCLEANFILES = $(DX_CLEANFILES)

utils-doc:
	(cd $(top_builddir)/src && $(MAKE) $(AM_MAKEFLAGS) docs)
	(cd $(top_builddir)/scripts && $(MAKE) $(AM_MAKEFLAGS) docs)
	(cd $(top_builddir)/airframe/doc && $(MAKE) $(AM_MAKEFLAGS) docs)

make-doc-path:
	mkdir -p $(top_builddir)/doc/html

# Doxygen adds both id="foo" and name="foo" attributes.  Remove name.
REPAIR_DOXY_DOCS = \
  if test -d "$${repair_dir}doc/html/libyaf" ; then \
    for i in `find "$${repair_dir}doc/html/libyaf" -name '*.html'` ; do \
      $(PERL) -i -lpwe 's/\b(id=("[^">]+")) +name=\2/$$1/g; s/\bname=("[^">]+") +(id=\1)/$$2/g;' $$i ; \
    done ; \
  fi

# Run the document marking script on files in the distdir
UPDATE_DOC_MARKINGS = \
  if test -f "$(UPDATE_MARKINGS)" ; then \
    find $(distdir) \
      -path $(distdir)/doc/html/libyaf -prune -o \
      -name libltdl -prune -o \
      -name lua -prune -o \
      -type f -print0 \
    | xargs -0 $(PERL) $(UPDATE_MARKINGS) ; \
  fi

dist-hook:
	$(UPDATE_DOC_MARKINGS)
	$(DX_ENV) SRCDIR=$(distdir) DOCDIR=$(distdir)/doc $(DX_DOXYGEN) $(DX_CONFIG)
	repair_dir="$(distdir)/" ; $(REPAIR_DOXY_DOCS)

docs: make-doc-path doxygen-doc utils-doc
	repair_dir="" ; $(REPAIR_DOXY_DOCS)


pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libyaf.pc

DISTCLEANFILES = $(YAF_SUMMARY_FILE)

EXTRA_DIST = \
    Doxyfile.in \
    DoxygenLayout.xml \
    LICENSE.txt \
    yaf.spec \
    yaf.spec.in

EXTRA_DIST += xml2fixbuf.xslt make-infomodel
