#######################################################################
# Copyright (C) 2008-2023 by Carnegie Mellon University.
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
# $SiLK: fglob.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

from subprocess import Popen, PIPE
from datetime import date, datetime, time
import errno
import sys

# Python 3.0 doesn't have basestring
if sys.hexversion >= 0x03000000:
    basestring = str

__all__ = ['FGlob']

rwfglob_executable = "rwfglob"

class FGlob(object):

    def __init__(self,
                 classname=None,
                 type=None,
                 sensors=None,
                 start_date=None,
                 end_date=None,
                 data_rootdir=None,
                 site_config_file=None):

        global rwfglob_executable

        if not (classname or type or sensors or start_date or end_date):
            raise ValueError("Must contain a specification")

        if end_date and not start_date:
            raise ValueError("An end_date requires a start_date")

        if isinstance(sensors, list):
            sensors = ",".join(map(str, sensors))
        elif isinstance(sensors, basestring):
            sensors = str(sensors)

        if isinstance(type, list):
            type = ",".join(type)
        elif isinstance(type, basestring):
            type = str(type)

        if isinstance(start_date, datetime):
            start_date = start_date.strftime("%Y/%m/%d:%H")
        elif isinstance(start_date, date):
            start_date = start_date.strftime("%Y/%m/%d")
        elif isinstance(start_date, time):
            start_date = datetime.combine(date.today(), start_date)
            start_date = start_date.strftime("%Y/%m/%d:%H")

        if isinstance(end_date, datetime):
            end_date = end_date.strftime("%Y/%m/%d:%H")
        elif isinstance(end_date, date):
            end_date = end_date.strftime("%Y/%m/%d")
        elif isinstance(end_date, time):
            end_date = datetime.combine(date.today(), end_date)
            end_date = end_date.strftime("%Y/%m/%d:%H")

        self.args = [rwfglob_executable, "--no-summary"]
        for val, arg in [(classname, "class"),
                         (type, "type"),
                         (sensors, "sensors"),
                         (start_date, "start-date"),
                         (end_date, "end-date"),
                         (data_rootdir, "data-rootdir"),
                         (site_config_file, "site-config-file")]:
            if val:
                if not isinstance(val, str):
                    raise ValueError("Specifications must be strings")
                self.args.append("--%s" % arg)
                self.args.append(val)

    def __iter__(self):
        try:
            rwfglob = Popen(self.args, bufsize=1, stdout=PIPE, close_fds=True,
                            universal_newlines=True)
        except OSError:
            # Handled using sys.exc_info() in order to compile on 2.4
            # and 3.0
            e = sys.exc_info()[1]
            if e.errno != errno.ENOENT:
                raise
            raise RuntimeError("Cannot find the %s program in PATH" %
                               self.args[0])
        for line in rwfglob.stdout:
            if rwfglob.returncode not in [None, 0]:
                raise RuntimeError("rwfglob failed")
            yield line.rstrip('\n\r')
