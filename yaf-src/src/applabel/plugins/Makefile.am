##  Copyright 2013-2023 Carnegie Mellon University
##  See license information in LICENSE.txt.

##  Process this file with automake to produce Makefile.in
##  ------------------------------------------------------------------------
##  Makefile.am (source)
##  autotools build system for YAF
##  ------------------------------------------------------------------------
##  Authors: Chris Inacio
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

AM_CFLAGS = $(WARN_CFLAGS) $(DEBUG_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir)/src/applabel $(YAF_CPPFLAGS) $(GLIB_CFLAGS) \
	$(OPENSSL_CPPFLAGS) $(libfixbuf_CFLAGS)

COMMON_PLUGIN_FLAGS = -version-info $(version_info) -module

pkglib_LTLIBRARIES = nullplugin.la dnsplugin.la tlsplugin.la slpplugin.la dumpplugin.la ircplugin.la pptpplugin.la nntpplugin.la tftpplugin.la mysqlplugin.la pop3plugin.la teredoplugin.la snmpplugin.la aolplugin.la socksplugin.la bgpplugin.la dhcpplugin.la piplugin.la rtpplugin.la palplugin.la proxyplugin.la dnp3plugin.la modbusplugin.la ethipplugin.la ldpplugin.la ldapplugin.la gh0stplugin.la netdgmplugin.la ntpplugin.la smtpplugin.la sshplugin.la

nullplugin_la_SOURCES = nullplugin.c
nullplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

dnsplugin_la_SOURCES = dnsplugin.c
dnsplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

tlsplugin_la_SOURCES = tlsplugin.c
tlsplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

slpplugin_la_SOURCES = slpplugin.c
slpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

sshplugin_la_SOURCES = sshplugin.c
sshplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

dumpplugin_la_SOURCES = outputDumper.c
dumpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

ircplugin_la_SOURCES = ircplugin.c
ircplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

pptpplugin_la_SOURCES = pptpplugin.c
pptpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

nntpplugin_la_SOURCES = nntpplugin.c
nntpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

tftpplugin_la_SOURCES = tftpplugin.c
tftpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

mysqlplugin_la_SOURCES = mysqlplugin.c
mysqlplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

pop3plugin_la_SOURCES = pop3plugin.c
pop3plugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

teredoplugin_la_SOURCES = teredoplugin.c
teredoplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

snmpplugin_la_SOURCES = snmpplugin.c
snmpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

aolplugin_la_SOURCES = aolplugin.c
aolplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

socksplugin_la_SOURCES = socksplugin.c
socksplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

bgpplugin_la_SOURCES = bgpplugin.c
bgpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

dhcpplugin_la_SOURCES = dhcpplugin.c
dhcpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

piplugin_la_SOURCES = piplugin.c
piplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

rtpplugin_la_SOURCES = rtpplugin.c
rtpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

palplugin_la_SOURCES = palplugin.c
palplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

proxyplugin_la_SOURCES = proxyplugin.c
proxyplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

dnp3plugin_la_SOURCES = dnp3plugin.c
dnp3plugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

ethipplugin_la_SOURCES = ethipplugin.c
ethipplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

modbusplugin_la_SOURCES = modbusplugin.c
modbusplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

ldpplugin_la_SOURCES = ldpplugin.c
ldpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

ldapplugin_la_SOURCES = ldapplugin.c
ldapplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

gh0stplugin_la_SOURCES = gh0stplugin.c
gh0stplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

netdgmplugin_la_SOURCES = netdgmplugin.c
netdgmplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

ntpplugin_la_SOURCES = ntpplugin.c
ntpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)

smtpplugin_la_SOURCES = smtpplugin.c
smtpplugin_la_LDFLAGS = $(COMMON_PLUGIN_FLAGS)
