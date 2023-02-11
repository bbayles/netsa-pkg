## Process this file with automake to produce Makefile.in
## ------------------------------------------------------------------------
## Makefile.am (source)
## ------------------------------------------------------------------------
## Copyright (C) 2018-2023 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------

BUILT_SOURCES = $(INFOMODEL_REGISTRY_INCLUDE_FILES)
EXTRA_DIST = $(INFOMODEL_REGISTRIES) $(INFOMODEL_REGISTRY_INCLUDE_FILES)

$(INFOMODEL_REGISTRY_INCLUDE_FILES): $(srcdir)/../xml2fixbuf.xslt
SUFFIXES = .xml .i
.xml.i:
	$(AM_V_GEN) $(XSLTPROC) --stringparam array-name infomodel_array_static_$* -o $@ $(srcdir)/../xml2fixbuf.xslt $<
