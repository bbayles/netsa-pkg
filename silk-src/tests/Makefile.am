## Copyright (C) 2009-2023 by Carnegie Mellon University.
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

# The targets in this file are used only by "make check" (and support
# targest things like "make clean" and "make dist")

# tell "make dist" what to package
EXTRA_DIST = SiLKTests.pm daemon_test.py make-data.pl make-scandata.pl \
	 make-sendrcv-data.pl pysilk-plugin.py \
	 $(TEST_BAG_FILES_SOURCE) $(TEST_CC_FILES_SOURCE) \
	 $(TEST_SET_FILES_SOURCE) $(TEST_PMAP_FILES_SOURCE)

# targets that 'make check' makes
check_DATA = silk.conf made-test-data empty.rwf \
	 made-bag-files made-pmap-files made-set-files $(pysilk_mini_install)

# additional files that may be created by hand or by "make check" in
# particular directories
other_files = data.txt columnar-data.txt data-v6.txt columnar-data-v6.txt \
	 scandata.rwf sips-004-008.rw small.pdu \
	 $(TEST_BAG_FILES) $(TEST_CC_FILES) \
	 $(TEST_PMAP_FILES) $(TEST_SET_FILES)


# commands
make_flows     = make-data.pl
make_scans     = make-scandata.pl
make_randfiles = make-sendrcv-data.pl


# the "silk.conf" file to use for testing
test_silk_conf = $(top_srcdir)/site/twoway/silk.conf

# get a local copy of silk.conf
silk.conf: $(test_silk_conf)
	-rm -f $@
	cp $(test_silk_conf) $@


# SiLK Applications required to build files used during tests and the
# rules to build the applications

RWBAGBUILD = $(top_builddir)/src/rwbag/rwbagbuild
RWCAT = $(top_builddir)/src/rwcat/rwcat
RWGEOIP2CCMAP = $(top_builddir)/src/rwpmap/rwgeoip2ccmap
RWPMAPBUILD = $(top_builddir)/src/rwpmap/rwpmapbuild
RWSETBUILD = $(top_builddir)/src/rwset/rwsetbuild
RWSETCAT   = $(top_builddir)/src/rwset/rwsetcat
RWTUC = $(top_builddir)/src/rwtuc/rwtuc

$(RWBAGBUILD):
	cd $(top_builddir)/src/rwbag && $(MAKE) rwbagbuild
$(RWCAT):
	cd $(top_builddir)/src/rwcat && $(MAKE) rwcat
$(RWGEOIP2CCMAP):
	cd $(top_builddir)/src/rwpmap && $(MAKE) rwgeoip2ccmap
$(RWPMAPBUILD):
	cd $(top_builddir)/src/rwpmap && $(MAKE) rwpmapbuild
$(RWSETBUILD):
	cd $(top_builddir)/src/rwset && $(MAKE) rwsetbuild
$(RWSETCAT):
	cd $(top_builddir)/src/rwset && $(MAKE) rwsetcat
$(RWTUC):
	cd $(top_builddir)/src/rwtuc && $(MAKE) rwtuc


# this is a data file to ensure header-only files are handled correctly
MAKE_EMPTY_RWF = \
	$(RWTUC) --site-config-file=silk.conf --output-path=$@ < /dev/null \
	|| { rm -f $@; exit 1; }

empty.rwf: $(RWTUC) silk.conf
	-rm -f $@
	$(MAKE_EMPTY_RWF)

# the 'made-test-data' target will cause the following data file(s) to
# be created.  these are the files that applications use for testing
data_rwf = data.rwf
v6data_rwf = data-v6.rwf
data_files = $(data_rwf)
if SK_ENABLE_IPV6
data_files += $(v6data_rwf)
else
other_files += $(v6data_rwf)
endif

# allow 'make data.rwf' to work
$(data_files): made-test-data

# rules to make the data file(s)
MAKE_TESTDATA_V4 = --ipv4-output='| $(RWTUC) --site-config-file=silk.conf --compression=best --output-path=$(data_rwf)'

if SK_ENABLE_IPV6

MAKE_TESTDATA_V6 = --ipv6-output='| $(RWTUC) --site-config-file=silk.conf --compression=best --output-path=$(v6data_rwf)'

endif


MAKE_TESTDATA = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	$(PERL) $${srcdir}$(make_flows) --status \
	$(MAKE_TESTDATA_V4) $(MAKE_TESTDATA_V6) \
	|| { rm -f $(data_files); exit 1; }

made-test-data: $(RWTUC) silk.conf $(make_flows)
	-rm -f $(data_files) $@
	$(MAKE_TESTDATA)
	date > $@

# sets for testing rwset*
TEST_SET_FILES = set1-v4.set set2-v4.set set3-v4.set set4-v4.set
if SK_ENABLE_IPV6
TEST_SET_FILES += set1-v6.set set2-v6.set set3-v6.set set4-v6.set
endif
TEST_SET_FILES_SOURCE = set1-v4.txt set2-v4.txt set3-v4.txt set4-v4.txt \
	 set1-v6.txt set2-v6.txt set3-v6.txt set4-v6.txt

TXT_TO_SET = \
	srcdir='' ; \
	test -f $< || srcdir='$(srcdir)/' ; \
	echo "$(RWSETBUILD) $${srcdir}$< $@" ; \
	$(RWSETBUILD) $${srcdir}$< $@ \
	|| { rm -f $@; exit 1; }

$(TEST_SET_FILES): $(RWSETBUILD)

made-set-files: $(TEST_SET_FILES)
	date > $@
.txt.set:
	-rm -f $@
	@$(TXT_TO_SET)


# bags for testing rwbag*
TEST_BAG_FILES = bag1-v4.bag bag2-v4.bag bag3-v4.bag
if SK_ENABLE_IPV6
TEST_BAG_FILES += bag1-v6.bag bag2-v6.bag bag3-v6.bag
endif
TEST_BAG_FILES_SOURCE = bag1-v4.txt bag2-v4.txt bag3-v4.txt \
	 bag1-v6.txt bag2-v6.txt bag3-v6.txt

TXT_TO_BAG = \
	srcdir='' ; \
	test -f $< || srcdir='$(srcdir)/' ; \
	echo "$(RWBAGBUILD) --bag-input=$${srcdir}$< --output-path=$@" ; \
	$(RWBAGBUILD) --bag-input=$${srcdir}$< --output-path=$@ \
	|| { rm -f $@; exit 1; }

$(TEST_BAG_FILES): $(RWBAGBUILD)

made-bag-files: $(TEST_BAG_FILES)
	date > $@
.txt.bag:
	-rm -f $@
	@$(TXT_TO_BAG)


# scan data for testing rwscan
MAKE_SCANDATA_RWF = \
	srcdir='' ; \
	test -f $(make_scans) || srcdir='$(srcdir)/' ; \
	{ $(PERL) $${srcdir}$(make_scans) --status \
	  | $(RWTUC) --site-config-file=silk.conf --compression=best --output-path=$@; } \
	|| { rm -f $@; exit 1; }

scandata.rwf: $(RWTUC) silk.conf $(make_scans)
	-rm -f $@
	$(MAKE_SCANDATA_RWF)

MAKE_SIPS_004_008 = \
	{ echo 4.0.0.0/6 \
	| $(RWSETBUILD) --record-version=4 \
	| $(RWSETCAT) --cidr=0 \
	| $(RWTUC) --site-config-file=silk.conf --fields=sip --stime=1000000000 \
	| $(RWCAT) --ipv4-output --compression=best --output-path=$@ ; } \
	|| { rm -f $@ ; exit 1; }

sips-004-008.rw: $(RWCAT) $(RWSETBUILD) $(RWSETCAT) $(RWTUC) silk.conf
	-rm -f $@
	$(MAKE_SIPS_004_008)

MAKE_SMALL_PDU = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$(make_flows) --max=50000 --pdu-output=$@" ; \
	$(PERL) $${srcdir}$(make_flows) --max=50000 --pdu-output=$@ \
	|| { rm -f $@; exit 1; }

# for testing rwguess and rwflowpack
small.pdu: $(make_flows)
	-rm -f $@
	$(MAKE_SMALL_PDU)


# for testing the country-code plug-ins
TEST_CC_FILES = fake-cc.pmap
if SK_ENABLE_IPV6
TEST_CC_FILES += fake-cc-v6.pmap
endif
TEST_CC_FILES_SOURCE = fake-cc.csv fake-cc-v6.csv

MAKE_FAKE_CC_V4 = \
	f=fake-cc.csv  ; srcdir='' ; \
	test -f $$f || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $(RWGEOIP2CCMAP) --mode=ipv4 < $${srcdir}$$f > $@" ; \
	$(PERL) $(RWGEOIP2CCMAP) --mode=ipv4 < $${srcdir}$$f > $@ \
	|| { rm -f $@; exit 1; }

MAKE_FAKE_CC_V6 = \
	f=fake-cc-v6.csv  ; srcdir='' ; \
	test -f $$f || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $(RWGEOIP2CCMAP) --mode=ipv6 < $${srcdir}$$f > $@" ; \
	$(PERL) $(RWGEOIP2CCMAP) --mode=ipv6 < $${srcdir}$$f > $@ \
	|| { rm -f $@; exit 1; }

fake-cc.pmap: $(RWGEOIP2CCMAP) fake-cc.csv
	-rm -f $@
	@$(MAKE_FAKE_CC_V4)

fake-cc-v6.pmap: $(RWGEOIP2CCMAP) fake-cc-v6.csv
	-rm -f $@
	@$(MAKE_FAKE_CC_V6)

# for testing the addrtype plug-in and rwpmap features
TEST_PMAP_FILES = address_types.pmap ip-map.pmap proto-port-map.pmap
if SK_ENABLE_IPV6
TEST_PMAP_FILES += ip-map-v6.pmap
endif
TEST_PMAP_FILES_SOURCE = address_types.txt ip-map.txt ip-map-v6.txt \
	 proto-port-map.txt

TXT_TO_PMAP = \
	srcdir='' ; \
	test -f $< || srcdir='$(srcdir)/' ; \
	echo "$(RWPMAPBUILD) --input-path=$${srcdir}$< --output-path=$@" ; \
	$(RWPMAPBUILD) --input-path=$${srcdir}$< --output-path=$@ \
	|| { rm -f $@; exit 1; }

$(TEST_PMAP_FILES): $(RWPMAPBUILD)

made-pmap-files: $(TEST_PMAP_FILES) $(TEST_CC_FILES)
	date > $@
.txt.pmap:
	-rm -f $@
	@$(TXT_TO_PMAP)


# for generating files to transfer between rwsender and rwreceiver;
# these are named random-bytes.a, random-bytes.b, ... random-bytes.j
MAKE_SENDRCV_FILES = \
	f=$(make_randfiles) ; srcdir='' ; \
	test -f $$f || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$$f --make-files --md5-out='$@'" ; \
	$(PERL) $${srcdir}$$f --make-files --md5-out='$@'

REMOVE_SENDRCV_FILES = \
	f=$(make_randfiles) ; srcdir='' ; \
	test -f $$f || srcdir='$(srcdir)/' ; \
	list=`$(PERL) $${srcdir}$$f --print-names` ; \
	echo "rm -f made-sendrcv-data $${list}" ; \
	rm -f made-sendrcv-data $${list}

made-sendrcv-data: $(make_randfiles)
	$(MAKE) remove-sendrcv-data
	@$(MAKE_SENDRCV_FILES)

remove-sendrcv-data:
	-@$(REMOVE_SENDRCV_FILES)

# local mini-installation of PySiLK, but only build it if PySiLK
# support is enabled.
if HAVE_PYTHON
pysilk_mini_install = pysilk-mini-install
else
pysilk_mini_install =
endif

pysilk-mini-install:
	test -d silk || mkdir silk
	cd '$(top_builddir)/src/pysilk' && $(MAKE) $@

pysilk-mini-uninstall:
	-if test -d silk ; then \
	     rm -f silk/*.py silk/*.pyc silk/pysilk* ; \
	     rmdir silk ; \
	 else \
	     : ; \
	 fi


# other useful targets

# data in the form that "rwcut --fields=... --delimited" creates
V4_DATA_TXT = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$(make_flows) --ipv4-output='$@'" ; \
	$(PERL) $${srcdir}$(make_flows) --ipv4-output='$@' \
	|| { rm -f '$@'; exit 1; }

V6_DATA_TXT = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$(make_flows) --ipv6-output='$@'" ; \
	$(PERL) $${srcdir}$(make_flows) --ipv6-output='$@' \
	|| { rm -f '$@'; exit 1; }

# in fixed-width columns (for IPv4, assumes --ipv6-policy=ignore)
V4_COLUMNAR_TXT = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$(make_flows) --columnar --ipv4-output='$@'" ; \
	$(PERL) $${srcdir}$(make_flows) --columnar --ipv4-output='$@' \
	|| { rm -f '$@'; exit 1; }

V6_COLUMNAR_TXT = \
	srcdir='' ; \
	test -f $(make_flows) || srcdir='$(srcdir)/' ; \
	echo "$(PERL) $${srcdir}$(make_flows) --columnar --ipv6-output='$@'" ; \
	$(PERL) $${srcdir}$(make_flows) --columnar --ipv6-output='$@' \
	|| { rm -f '$@'; exit 1; }

data.txt: $(make_flows)
	-rm -f $@
	@$(V4_DATA_TXT)

data-v6.txt: $(make_flows)
	-rm -f $@
	@$(V6_DATA_TXT)

columnar-data.txt: $(make_flows)
	-rm -f $@
	@$(V4_COLUMNAR_TXT)

columnar-data-v6.txt: $(make_flows)
	-rm -f $@
	@$(V6_COLUMNAR_TXT)


# have all outputs depend on this Makefile
$(check_DATA) $(data_files) $(other_files) made-sendrcv-data: Makefile

.PHONY: pysilk-mini-install pysilk-mini-uninstall remove-sendrcv-data

# clean up the files we create
CLEANFILES = $(check_DATA) $(data_files) $(other_files) \
	 config_vars.pyc daemon_test.pyc

clean-local: remove-sendrcv-data pysilk-mini-uninstall
