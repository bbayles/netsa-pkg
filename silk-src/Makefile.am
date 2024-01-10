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
## RCSIDENT("$SiLK: Makefile.am 391c69a44422 2023-06-22 20:19:07Z mthomas $")

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = tests src site
DIST_SUBDIRS = doc $(SUBDIRS)

EXTRA_DIST = LICENSE.txt README.txt

# extra configuration files
EXTRA_DIST += $(PYTHON_INFO_PROG)

dist-hook: template-dir cvs-id-to-silk

template-dir:
	mkdir $(distdir)/src/template
	list="Makefile.am c-application.c c-file.c c-plugin.c header.h python.py" ; \
        for f in $$list ; do \
	    cp -p $(srcdir)/src/template/$$f $(distdir)/src/template/$$f ; \
	done

cvs-id-to-silk:
	perl -MFile::Find -0777 -we '$$File::Find::dont_use_nlink=1; for $$d (@ARGV){find(sub{$$n=$$File::Find::name;return if -l; if (/^(\.git|\.hg|\.svn|CVS)$$/ && -d) {$$File::Find::prune = 1;return;} return unless -f _ && -w _ && -T; ($$a,$$m)=((stat(_))[8,9]); open(F,"+<$$_") or die "open $$n: $$!\n"; $$f=<F>; $$f=~s/\$$Id\:/\$$SiLK:/g; seek F,0,0 or die "seek $$n:$$!\n"; print F $$f; close F or die "$$n: $$!\n"; utime $$a,$$m,$$_ or die "utime $$n: $$!\n"},$$d);}' $(distdir)


install-data-hook: $(PYTHON_REMINDER) remind-silk-conf

remind-silk-conf:
	@echo ''
	@echo '************************************************************'
	@echo 'Example site configuration files have been installed in'
	@echo '    $(pkgdatadir)/*-silk.conf'
	@echo 'Choose the file that matches your packing logic plug-in'
	@echo 'and/or installation, rename it to silk.conf, customize it,'
	@echo 'and copy it to the root of the data directory:'
	@echo '    $(SILK_DATA_ROOTDIR)/silk.conf'
	@echo '************************************************************'



if HAVE_PYTHON
if BUILD_ANALYSIS_TOOLS
PYTHON_REMINDER = remind-python
endif
endif

PYSILK_INSTALL_TXT = INSTALL-PySiLK.txt

remind-python: $(PYSILK_INSTALL_TXT)
	-@if test "x$(PYTHON_SITE_PKG)" != "x$(PYTHON_DEFAULT_SITE_PKG)" ; then \
	cat $(PYSILK_INSTALL_TXT) ; \
	fi

$(PYSILK_INSTALL_TXT): Makefile
	-rm -f $@
	touch $@
	@echo '************************************************************' >> $@
	@echo "The PySiLK modules were installed outside Python's default" >> $@
	@echo "site directory.  To use SiLK in Python, set or modify your" >> $@
	@echo 'PYTHONPATH environment variable to include the directory:' >> $@
	@echo '    $(PYTHON_SITE_PKG)' >> $@
	@echo '************************************************************' >> $@


CLEANFILES = $(PYSILK_INSTALL_TXT)

DISTCLEANFILES = silk-$(PACKAGE_VERSION).spec $(SILK_SUMMARY_FILE)
