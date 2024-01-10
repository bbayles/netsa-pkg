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
## RCSIDENT("$SiLK: build.mk 391c69a44422 2023-06-22 20:19:07Z mthomas $")

#  This file contains common rules included into every Makefile.in


########  MANUAL PAGE SUPPORT
#
#  Rules to build (and clean) the manual pages (troff) from the Perl
#  POD (Plain Old Documentation) source files
#
POD2MAN_ARGS = --center="SiLK Tool Suite" --release="$(PACKAGE_STRING)"

pod_edit = sed \
	-e 's|@SILK_DATA_ROOTDIR[@]|$(SILK_DATA_ROOTDIR)|g' \
	-e 's|@prefix[@]|$(prefix)|g'

.pod.man:
	$(AM_V_GEN)$(POD2MAN) $(POD2MAN_ARGS) $< > $@
.pod.1:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=1 --name="$*" $(POD2MAN_ARGS) > "$@"
.pod.2:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=2 --name="$*" $(POD2MAN_ARGS) > "$@"
.pod.3:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=3 --name="$*" $(POD2MAN_ARGS) > "$@"
.pod.5:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=5 --name="$*" $(POD2MAN_ARGS) > "$@"
.pod.7:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=7 --name="$*" $(POD2MAN_ARGS) > "$@"
.pod.8:
	$(AM_V_GEN)$(pod_edit) $< | $(POD2MAN) --section=8 --name="$*" $(POD2MAN_ARGS) > "$@"

clean-local: clean-remove-man
clean-remove-man:
	-test -z "$(MANS)" || rm -f $(MANS)



########  PERL SCRIPT BUILD
#
#  The following variables convert the Perl script source file
#  "SCRIPT.in" to the execuable "SCRIPT".  To use them, add the
#  following for each SCRIPT script to the appropriate Makefile.am
#
#  SCRIPT: SCRIPT.in
#	$(MAKE_PERL_SCRIPT)

make_perl_script_edit = sed \
	-e 's|@PERL[@]|$(PERL)|g' \
	-e 's|@PACKAGE_STRING[@]|$(PACKAGE_STRING)|g' \
	-e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g' \
	-e 's|@SILK_VERSION_INTEGER[@]|$(SILK_VERSION_INTEGER)|g'

MAKE_PERL_SCRIPT = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$@.in || srcdir=$(srcdir)/ ; \
  $(make_perl_script_edit) "$${srcdir}$@.in" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@



########  PYTHON SCRIPT BUILD
#
#  The following variables convert the Python script source file
#  "SCRIPT.in" to the execuable "SCRIPT".  To use them, add the
#  following for each SCRIPT script to the appropriate Makefile.am
#
#  SCRIPT: SCRIPT.in
#	$(MAKE_PYTHON_SCRIPT)
#
#  This script assumes there is a single source for the Python script,
#  and it will work work where we have different scripts depending on
#  the version of Python in use.

make_python_script_edit = sed \
	-e 's|@PYTHON[@]|$(PYTHON)|g' \
	-e 's|@PACKAGE_STRING[@]|$(PACKAGE_STRING)|g' \
	-e 's|@PACKAGE_BUGREPORT[@]|$(PACKAGE_BUGREPORT)|g'

MAKE_PYTHON_SCRIPT = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f ./$@.in || srcdir=$(srcdir)/ ; \
  $(make_python_script_edit) "$${srcdir}$@.in" >$@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@



########  DAEMON CONFIGURATION
#
#  The following support the .conf and .init.d files used for daemon
#  configuration

#  Convert @foo@ int the .conf and .init.d files to path names
edit_conf_init_d = sed \
	-e 's|@SILK_DATA_ROOTDIR[@]|$(SILK_DATA_ROOTDIR)|g' \
	-e 's|@localstatedir[@]|$(localstatedir)|g' \
	-e 's|@sbindir[@]|$(sbindir)|g' \
	-e 's|@sysconfdir[@]|$(sysconfdir)|g' \
	-e 's|@myprog[@]|'$${myprog}'|g'

#  The following variable converts DAEMON.conf.in to DAEMON.conf.  To
#  use it, add the following for each DAEMON.conf file to the
#  appropriate Makefile.am:
#
#  DAEMON.conf: DAEMON.conf.in Makefile
#	$(MAKE_CONF_FILE)
#
#  To ensure it gets built, add DAEMON.conf to the "all-local:" target
#  in the Makefile.am

MAKE_CONF_FILE = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f "./$@.in" || srcdir="$(srcdir)/" ; \
  myprog=`echo '$@' | sed -e 's|^.*/||;' -e 's|\.conf$$||;$(transform)'` ; \
  $(edit_conf_init_d) "$${srcdir}$@.in" > $@.tmp && \
  mv $@.tmp $@

#  A rule to install the DAEMON.conf files into $(conf_file_dir) and a
#  second rule to uninstall them.  For these rules to work, add the
#  following to the appropriate Makefile.am:
#
#  conf_files = DAEMON1.conf DAEMON2.conf
#  install-data-local: install-conf-files
#  uninstall-local: uninstall-conf-files

#  The install directory is $(prefix)/share/silk/etc/
conf_file_dir = $(pkgdatadir)/etc

install-conf-files: $(conf_files)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(conf_file_dir)
	@list='$(conf_files)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo "$$p" | sed -e 's,^.*/,,;s/\.conf$$//;$(transform);s/$$/\.conf/'`; \
	  echo " $(INSTALL_DATA) '$$d$$p' '$(DESTDIR)$(conf_file_dir)/$$f'"; \
	  $(INSTALL_DATA) "$$d$$p" "$(DESTDIR)$(conf_file_dir)/$$f"; \
	done

uninstall-conf-files:
	@$(NORMAL_UNINSTALL)
	@list='$(conf_files)'; for p in $$list; do \
	  f=`echo "$$p" | sed -e 's,^.*/,,;s/\.conf$$//;$(transform);s/$$/\.conf/'`; \
	  echo " rm -f '$(DESTDIR)$(conf_file_dir)/$$f'"; \
	  rm -f "$(DESTDIR)$(conf_file_dir)/$$f"; \
	done

#  The following variable converts DAEMON.init.d.in to DAEMON.init.d.
#  To use it, add the following for each DAEMON.init.d script to the
#  appropriate Makefile.am:
#
#  DAEMON.init.d: DAEMON.init.d.in Makefile
#	$(MAKE_INIT_D_SCRIPT)
#
#  To ensure it gets built, add DAEMON.init.d to the "all-local:"
#  target in the Makefile.am

MAKE_INIT_D_SCRIPT = $(AM_V_GEN) \
  rm -f $@ $@.tmp ; \
  srcdir='' ; \
  test -f "./$@.in" || srcdir="$(srcdir)/" ; \
  myprog=`echo '$@' | sed -e 's|^.*/||;' -e 's|\.init\.d$$||;$(transform)'` ; \
  $(edit_conf_init_d) "$${srcdir}$@.in" > $@.tmp && \
  chmod +x $@.tmp && \
  mv $@.tmp $@

#  A rule to install the DAEMON.init.d scripts into
#  $(init_d_scripts_dir) and a second rule to uninstall them.  For
#  these rules to work, add the following to the appropriate
#  Makefile.am:
#
#  init_d_scripts = DAEMON1.init.d DAEMON2.init.d
#  install-data-local: install-init-d-scripts
#  uninstall-local: uninstall-init-d-scripts

#  The install directory is $(prefix)/share/silk/etc/init.d/
init_d_scripts_dir = $(pkgdatadir)/etc/init.d

install-init-d-scripts: $(init_d_scripts)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(init_d_scripts_dir)
	@list='$(init_d_scripts)'; for p in $$list; do \
	  if test -f "$$p"; then d=; else d="$(srcdir)/"; fi; \
	  f=`echo "$$p" | sed -e 's,^.*/,,;s,\.init\.d$$,,;$(transform)'`; \
	  echo " $(INSTALL_SCRIPT) '$$d$$p' '$(DESTDIR)$(init_d_scripts_dir)/$$f'"; \
	  $(INSTALL_SCRIPT) "$$d$$p" "$(DESTDIR)$(init_d_scripts_dir)/$$f"; \
	done

uninstall-init-d-scripts:
	@$(NORMAL_UNINSTALL)
	@list='$(init_d_scripts)'; for p in $$list; do \
	  f=`echo "$$p" | sed -e 's,^.*/,,;s,\.init\.d$$,,;$(transform)'`; \
	  echo " rm -f '$(DESTDIR)$(init_d_scripts_dir)/$$f'"; \
	  rm -f "$(DESTDIR)$(init_d_scripts_dir)/$$f"; \
	done



########  TESTING (MAKE CHECK) SUPPORT
#
#  Rules to build various files used during testing.  To actually
#  build these files, add the appropriate variable(s) to check_DATA
#
SILK_TESTBAGS = $(top_builddir)/tests/made-bag-files
$(SILK_TESTBAGS):
	cd $(top_builddir)/tests && $(MAKE) made-bag-files

SILK_TESTDATA = $(top_builddir)/tests/made-test-data
$(SILK_TESTDATA):
	cd $(top_builddir)/tests && $(MAKE) check

SILK_TESTPDU = $(top_builddir)/tests/small.pdu
$(SILK_TESTPDU):
	cd $(top_builddir)/tests && $(MAKE) small.pdu

SILK_TESTPMAPS = $(top_builddir)/tests/made-pmap-files
$(SILK_TESTPMAPS):
	cd $(top_builddir)/tests && $(MAKE) made-pmap-files

SILK_TESTSCAN =	$(top_builddir)/tests/scandata.rwf
$(SILK_TESTSCAN):
	cd $(top_builddir)/tests && $(MAKE) scandata.rwf

SILK_SENDRCVDATA = $(top_builddir)/tests/made-sendrcv-data
$(SILK_SENDRCVDATA):
	cd $(top_builddir)/tests && $(MAKE) made-sendrcv-data

SILK_TESTSETS = $(top_builddir)/tests/made-set-files
$(SILK_TESTSETS):
	cd $(top_builddir)/tests && $(MAKE) made-set-files

SILK_TESTSIPS004 = $(top_builddir)/tests/sips-004-008.rw
$(SILK_TESTSIPS004):
	cd $(top_builddir)/tests && $(MAKE) sips-004-008.rw

# Ensure the local 'tests' directory exists
SILK_TESTSDIR = ./tests/touch-dir
$(SILK_TESTSDIR):
	test -d ./tests || mkdir ./tests
	touch $@

# Set defaults to use for the testing harness used by "make check"
#
AM_TESTS_ENVIRONMENT = \
	srcdir=$(srcdir) ; export srcdir ; \
	top_srcdir=$(top_srcdir) ; export top_srcdir ; \
	top_builddir=$(top_builddir) ; export top_builddir ;
PL_LOG_COMPILER = $(PERL)
AM_PL_LOG_FLAGS = -I$(top_srcdir)/tests -w

LOG_COMPILER = $(PL_LOG_COMPILER)
AM_LOG_FLAGS = $(AM_PL_LOG_FLAGS)

clean-local: clean-remove-tests-touch-dir
clean-remove-tests-touch-dir:
	-rm -f $(SILK_TESTSDIR)

# A rule to rebuild all the automatically generated tests
# This will rebuild all the test files in tests/
sk-make-silktests: all $(check_PROGRAMS) $(check_DATA) $(srcdir)/tests/make-tests.pl
	$(AM_TESTS_ENVIRONMENT) $(LOG_COMPILER) $(AM_LOG_FLAGS) $(srcdir)/tests/make-tests.pl



.PHONY: clean-remove-man clean-remove-tests-touch-dir \
	install-conf-files uninstall-conf-files \
	install-init-d-scripts uninstall-init-d-scripts \
	sk-make-silktests
