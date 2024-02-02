#######################################################################
# Copyright (C) 2011-2023 by Carnegie Mellon University.
#
# @OPENSOURCE_LICENSE_START@
#
# SiLK 3.22.0
#
# Copyright 2023 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
# THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
# ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
# INFRINGEMENT.
#
# Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
# contact permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for
# non-US Government use and distribution.
#
# GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
#
# Contract No.: FA8702-15-D-0002
# Contractor Name: Carnegie Mellon University
# Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
#
# The Government's rights to use, modify, reproduce, release, perform,
# display, or disclose this software are restricted by paragraph (b)(2) of
# the Rights in Noncommercial Computer Software and Noncommercial Computer
# Software Documentation clause contained in the above identified
# contract. No restrictions apply after the expiration date shown
# above. Any reproduction of the software or portions thereof marked with
# this legend must also reproduce the markings.
#
# Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
# Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each
# subject to its own license.
#
# DM23-0973
#
# @OPENSOURCE_LICENSE_END@
#
#######################################################################

#######################################################################
# $SiLK: _netsa_silk.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

"""
The netsa_silk module contains a shared API for working with common
Internet data in both netsa-python and PySiLK.  If netsa-python is
installed but PySiLK is not, the less efficient but more portable
pure-Python version of this functionality that is included in
netsa-python is used.  If PySiLK is installed, then the
high-performance C version of this functionality that is included in
PySiLK is used.
"""

# This module provides the symbols exported by PySiLK for the
# netsa_silk API.  It exists to rename PySiLK symbols that have a
# different name from the netsa_silk symbols, and to constrain the set
# of PySiLK symbols that are exported.  If a new symbol is added (to
# provide a new feature), it need only be added here and it will
# automatically be exported by netsa_silk.

from silk import (
    ipv6_enabled as has_IPv6Addr,
    IPAddr, IPv4Addr, IPv6Addr,
    IPSet as ip_set,
    IPWildcard,
    TCPFlags,

    TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR,
    silk_version
)

# PySiLK API version
__version__ = "1.0"

# Implementation version
__impl_version__ = " ".join(["SiLK", silk_version()])

__all__ = """
    has_IPv6Addr
    IPAddr IPv4Addr IPv6Addr
    ip_set
    IPWildcard
    TCPFlags

    TCP_FIN TCP_SYN TCP_RST TCP_PSH TCP_ACK TCP_URG TCP_ECE TCP_CWR

    __version__
    __impl_version__
""".split()
