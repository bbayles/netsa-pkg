##  Copyright 2005-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  ------------------------------------------------------------------------
##  Makefile.am (documentation)
##  autotools build system for Airframe
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

man1_MANS = airdaemon.1 filedaemon.1
PODFILES = airdaemon.pod filedaemon.pod
HTMLFILES = airdaemon.html filedaemon.html

.pod.1:
	$(POD2MAN) $(AIRFRAME_POD2MAN_ARGS) --section=1 $< $@

.pod.html:
	$(POD2HTML) --noindex --infile="$<" --outfile="$@"
	$(top_srcdir)/doc/add-header.pl "$@"

dist-hook: $(HTMLFILES)
	mkdir -p $(top_distdir)/doc/html
	cp $(HTMLFILES) $(top_distdir)/doc/html

copy-man-pages: $(HTMLFILES)
	mkdir -p $(top_builddir)/doc/html
	cp $(HTMLFILES) $(top_builddir)/doc/html

docs: $(man1_MANS) copy-man-pages

clean-docs:
	rm -f $(man1_MANS) $(HTMLFILES)

clean-local:
	rm -f pod2htm*.tmp

MOSTLYCLEANFILES = $(man1_MANS) $(HTMLFILES)

EXTRA_DIST =    $(PODFILES)                      \
                $(man1_MANS)                     \
html/airlock_8h-source.html \
html/airlock_8h.html \
html/airopt_8h-source.html \
html/airopt_8h.html \
html/airutil_8h-source.html \
html/airutil_8h.html \
html/annotated.html \
html/daeconfig_8h-source.html \
html/daeconfig_8h.html \
html/doxygen.css \
html/doxygen.png \
html/files.html \
html/functions.html \
html/functions_vars.html \
html/globals.html \
html/globals_eval.html \
html/globals_func.html \
html/globals_type.html \
html/globals_vars.html \
html/index.html \
html/logconfig_8h-source.html \
html/logconfig_8h.html \
html/mio_8h-source.html \
html/mio_8h.html \
html/mio__config_8h-source.html \
html/mio__config_8h.html \
html/mio__sink__file_8h-source.html \
html/mio__sink__file_8h.html \
html/mio__sink__multi_8h-source.html \
html/mio__sink__multi_8h.html \
html/mio__sink__tcp_8h-source.html \
html/mio__sink__tcp_8h.html \
html/mio__sink__udp_8h-source.html \
html/mio__sink__udp_8h.html \
html/mio__source__file_8h-source.html \
html/mio__source__file_8h.html \
html/mio__source__pcap_8h-source.html \
html/mio__source__pcap_8h.html \
html/mio__source__tcp_8h-source.html \
html/mio__source__tcp_8h.html \
html/mio__source__udp_8h-source.html \
html/mio__source__udp_8h.html \
html/mio__stdio_8h-source.html \
html/mio__stdio_8h.html \
html/privconfig_8h-source.html \
html/privconfig_8h.html \
html/struct___air_lock.html \
html/struct___m_i_o_app_driver.html \
html/struct___m_i_o_sink.html \
html/struct___m_i_o_sink_file_config.html \
html/struct___m_i_o_source.html \
html/struct___m_i_o_source_file_config.html \
html/struct___m_i_o_source_p_cap_file_config.html \
html/struct___m_i_o_source_p_cap_live_config.html \
html/struct___m_i_o_source_t_c_p_config.html \
html/tab_b.gif \
html/tab_l.gif \
html/tab_r.gif \
html/tabs.css \
html/tools.css
