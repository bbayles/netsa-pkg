## Process this file with automake to produce Makefile.in

## ------------------------------------------------------------------------
## Makefile.am (startup)
## autotools build system for NAF applications
## ------------------------------------------------------------------------
## Copyright (C) 2005-2023 Carnegie Mellon University. All Rights Reserved.
## ------------------------------------------------------------------------
## Authors: Brian Trammell 
## ------------------------------------------------------------------------
## GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
## Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
## ------------------------------------------------------------------------

# This is a sample yaf Lua-based configuration file that replaces most
# command line arguments.  Install it in $prefix/share/yaf/yaf.init
dist_pkgdata_DATA = yaf.init

# These are used to add yaf to the boot sequence.  Always install
# yaf.conf into $prefix/etc. We rely on rpmbuild to move init.d/yaf
# into place.
EXTRA_DIST = yaf.conf.in init.d/yaf.in

sysconf_DATA = yaf.conf

# Other config files that depend on how yaf is configured
dist_sysconf_DATA = yafApplabelRules.conf

if PLUGINENABLE
dist_sysconf_DATA += yafDPIRules.conf dhcp_fingerprints.conf
endif

if P0FENABLE
dist_sysconf_DATA += p0f.fp
endif
