## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## ------------------------------------------------------------------------
## @OPENSOURCE_LICENSE_START@
## libfixbuf 2.0
##
## Copyright 2018-2023 Carnegie Mellon University. All Rights Reserved.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE
## ENGINEERING INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS"
## BASIS. CARNEGIE MELLON UNIVERSITY MAKES NO WARRANTIES OF ANY KIND,
## EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER INCLUDING, BUT NOT
## LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR MERCHANTABILITY,
## EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
## MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR
## COPYRIGHT INFRINGEMENT.
##
## Released under a GNU-Lesser GPL 3.0-style license, please see
## LICENSE.txt or contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for
## public release and unlimited distribution.  Please see Copyright
## notice for non-US Government use and distribution.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent
## and Trademark Office by Carnegie Mellon University.
##
## DM18-0325
## @OPENSOURCE_LICENSE_END@
## ------------------------------------------------------------------------

BUILT_SOURCES = $(INFOMODEL_REGISTRY_INCLUDE_FILES)
EXTRA_DIST = $(INFOMODEL_REGISTRIES) $(INFOMODEL_REGISTRY_INCLUDE_FILES)

$(INFOMODEL_REGISTRY_INCLUDE_FILES): $(srcdir)/../xml2fixbuf.xslt
SUFFIXES = .xml .i
.xml.i:
	$(AM_V_GEN) $(XSLTPROC) --stringparam array-name infomodel_array_static_$* -o $@ $(srcdir)/../xml2fixbuf.xslt $<
