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

SILK_SRC_MAKE_BASE_LIBS = \
	 libsilk

SILK_SRC_MAKE_PACKING_LIBS = \
	 libflowsource

SILK_SRC_MAKE_RWFILTER = \
         rwfilter \
         plugins

SILK_SRC_MAKE_PYTHON_PLUGIN = \
         pysilk

SILK_SRC_MAKE_PACKING_TOOLS = \
         flowcap \
         rwflowpack \
         rwpollexec \
         sendrcv

SILK_SRC_MAKE_ANALYSIS_TOOLS = \
         num2dot \
         rwaddrcount \
         rwaggbag \
         rwappend \
         rwbag \
         rwcat \
         rwcompare \
         rwconvert \
         rwcount \
         rwcut \
         rwfileinfo \
         rwgroup \
         rwmatch \
         rwnetmask \
         rwpmap \
         rwrandomizeip \
         rwrecgenerator \
         rwresolve \
         rwscan \
         rwset \
         rwsiteinfo \
         rwsort \
         rwsplit \
         rwstats \
         rwswapbytes \
         rwtotal \
         rwtuc

# Conditional analysis tools
SILK_SRC_MAKE_ANALYSIS_FIXBUF = rwipfix
SILK_SRC_MAKE_ANALYSIS_IPA = rwipa
SILK_SRC_MAKE_ANALYSIS_PCAP = rwptoflow
SILK_SRC_MAKE_ANALYSIS_PYTHONBIN = rwids

# Experimental code



SUBDIRS = $(SILK_SRC_MAKE_BASE_LIBS)

if BUILD_ANALYSIS_TOOLS


if HAVE_PYTHON
SUBDIRS += $(SILK_SRC_MAKE_PYTHON_PLUGIN)
endif

SUBDIRS += $(SILK_SRC_MAKE_RWFILTER)

SUBDIRS += $(SILK_SRC_MAKE_ANALYSIS_TOOLS)

if HAVE_PCAP
SUBDIRS += $(SILK_SRC_MAKE_ANALYSIS_PCAP)
endif
if HAVE_PYTHONBIN
SUBDIRS += $(SILK_SRC_MAKE_ANALYSIS_PYTHONBIN)
endif
if HAVE_IPA
SUBDIRS += $(SILK_SRC_MAKE_ANALYSIS_IPA)
endif

# Add the packing libraries here if either fixbuf is available or if
# the packing tools are being built.
if HAVE_FIXBUF
SUBDIRS += $(SILK_SRC_MAKE_PACKING_LIBS)
else
if BUILD_PACKING_TOOLS
SUBDIRS += $(SILK_SRC_MAKE_PACKING_LIBS)
endif
endif

if HAVE_FIXBUF
SUBDIRS += $(SILK_SRC_MAKE_ANALYSIS_FIXBUF)
endif

if BUILD_PACKING_TOOLS
SUBDIRS += $(SILK_SRC_MAKE_PACKING_TOOLS)
endif

else !BUILD_ANALYSIS_TOOLS


if BUILD_PACKING_TOOLS
SUBDIRS += \
	$(SILK_SRC_MAKE_PACKING_LIBS) \
	$(SILK_SRC_MAKE_PACKING_TOOLS)
endif

endif !BUILD_ANALYSIS_TOOLS

SUBDIRS += include/silk

DIST_SUBDIRS = \
	 $(SILK_SRC_MAKE_BASE_LIBS) \
	 $(SILK_SRC_MAKE_PACKING_LIBS) \
	 include/silk \
	 $(SILK_SRC_MAKE_RWFILTER) \
	 $(SILK_SRC_MAKE_PYTHON_PLUGIN) \
         $(SILK_SRC_MAKE_PACKING_TOOLS) \
	 $(SILK_SRC_MAKE_ANALYSIS_TOOLS) \
         $(SILK_SRC_MAKE_ANALYSIS_PCAP) \
         $(SILK_SRC_MAKE_ANALYSIS_IPA) \
	 $(SILK_SRC_MAKE_ANALYSIS_PYTHONBIN) \
	 $(SILK_SRC_MAKE_ANALYSIS_FIXBUF)
