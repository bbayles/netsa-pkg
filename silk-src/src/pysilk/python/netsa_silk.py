# Copyright 2008-2023 by Carnegie Mellon University

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

"""
The netsa_silk module contains a shared API for working with common
Internet data in both netsa-python and PySiLK.  If netsa-python is
installed but PySiLK is not, the less efficient but more portable
pure-Python version of this functionality that is included in
netsa-python is used.  If PySiLK is installed, then the
high-performance C version of this functionality that is included in
PySiLK is used.
"""

# This module exists only to import the needed functionality from
# either PySiLK (via the internal silk._netsa_silk module), or
# netsa-python (via the internal netsa._netsa_silk module) and then
# re-export it.  All information (including the list of symbols to
# export) comes from the module providing the functionality, so that
# this module will never have to change and may remain common to both
# PySiLK and netsa-python installs.  (That is: Since it's always the
# same, it's acceptable for both sources to install the file without
# fear of overwriting each other.

import os

try:
    if os.getenv("NETSA_SILK_DISABLE_PYSILK"):
        raise ImportError("netsa_silk PySiLK support disabled")
    import silk._netsa_silk
    from silk._netsa_silk import *
    __all__ = silk._netsa_silk.__all__
except ImportError:
    try:
        if os.getenv("NETSA_SILK_DISABLE_NETSA_PYTHON"):
            raise ImportError("netsa_silk netsa-python support disabled")
        import netsa._netsa_silk
        from netsa._netsa_silk import *
        __all__ = netsa._netsa_silk.__all__
    except ImportError:
        import_error = ImportError(
            "Cannot locate netsa_silk implementation during import")
        raise import_error
