## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## autotools build system for libfixbuf
## ------------------------------------------------------------------------
## Copyright (C) 2018 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## GNU Lesser GPL Rights pursuant to Version 2.1, February 1999
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

BUILT_SOURCES = $(INFOMODEL_REGISTRY_INCLUDE_FILES)
EXTRA_DIST = $(INFOMODEL_REGISTRIES) $(INFOMODEL_REGISTRY_INCLUDE_FILES)

$(INFOMODEL_REGISTRY_INCLUDE_FILES): $(srcdir)/../xml2fixbuf.xslt
SUFFIXES = .xml .i
.xml.i:
	$(AM_V_GEN) $(XSLTPROC) --stringparam array-name infomodel_array_static_$* -o $@ $(srcdir)/../xml2fixbuf.xslt $<
