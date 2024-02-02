#!/usr/bin/env python
#######################################################################
# Copyright (C) 2009-2023 by Carnegie Mellon University.
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
# $SiLK: rwflowappend-daemon.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################
from __future__ import print_function
import optparse
import subprocess
import signal
import re
import time
import traceback
import shutil
import sys
import os
import os.path

from daemon_test import Dirobject, TimedReadline, string_write

VERBOSE = False
logfile = None

def base_log(*args):
    global VERBOSE
    global logfile

    out = ' '.join(str(x) for x in args)
    if out[-1] != '\n':
        out += '\n'
    string_write(logfile, out)
    if VERBOSE:
        sys.stderr.write(out)

def log(*args):
    out = "%s: %s:" % (time.asctime(), os.path.basename(sys.argv[0]))
    base_log(out, *args)

def _copy_files(dirobj, spec, fn):
    split = [x.split(':') for x in spec]
    for f, d in split:
        if d not in dirobj.dirs:
            raise RuntimeError("Unknown destination directory")
        fn(f, dirobj.dirname[d])

def copy_files(dirobj, spec):
    return _copy_files(dirobj, spec, shutil.copy)

def move_files(dirobj, spec):
    return _copy_files(dirobj, spec, shutil.move)

def main():
    global VERBOSE
    global logfile
    parser = optparse.OptionParser()
    parser.add_option("--copy", action="append", type="string", dest="copy",
                      default=[])
    parser.add_option("--move", action="append", type="string", dest="move",
                      default=[])
    parser.add_option("--file-limit", action="store", type="int",
                      dest="file_limit", default=0)
    parser.add_option("--no-archive", action="store_true", dest="no_archvie",
                      default=False)
    parser.add_option("--basedir", action="store", type="string",
                      dest="basedir")
    parser.add_option("--daemon-timeout", action="store", type="int",
                      dest="daemon_timeout", default=60)
    parser.add_option("--verbose", action="store_true", dest="verbose",
                      default=False)
    parser.add_option("--overwrite-dirs", action="store_true", dest="overwrite",
                      default=False)
    parser.add_option("--log-level", action="store", type="string",
                      dest="log_level", default="info")
    (options, args) = parser.parse_args()
    VERBOSE = options.verbose

    # Create the dirs
    dirobj = Dirobject(overwrite=options.overwrite, basedir=options.basedir)
    dirobj.dirs = ['incoming', 'archive', 'error', 'root', 'log']
    dirobj.create_dirs()

    # Make the log file
    logfile = open(dirobj.get_path('log', 'rwflowappend-daemon.log'), 'wb', 0)

    # Generate the subprocess arguments
    args += ['--log-dest', 'stderr',
             '--log-level', options.log_level,
             '--no-daemon',
             '--root-directory', dirobj.dirname['root'],
             '--incoming-directory', dirobj.dirname['incoming'],
             '--error-directory', dirobj.dirname['error']]

    if not options.no_archvie:
        args += ['--archive-directory', dirobj.dirname['archive']]


    progname = os.environ.get("RWFLOWAPPEND",
                              os.path.join('.', 'rwflowappend'))
    args = progname.split() + args

    # Set up state variables
    count = 0
    clean = False
    term = False
    send_list = None
    limit = len(options.copy) + len(options.move) + options.file_limit
    regexp = re.compile("APPEND OK")
    closing = re.compile("Stopped logging")

    if 0 == limit:
        print("ERROR: File limit is zero")
        base_log("ERROR: File limit is zero")
        sys.exit(1)

    # Copy or move data
    copy_files(dirobj, options.copy)
    move_files(dirobj, options.move)

    # Note the time
    starttime = time.time()
    shutdowntime = None

    # Start the process
    log("Running", "'%s'" % "' '".join(args))
    proc = subprocess.Popen(args, stderr=subprocess.PIPE)
    line_reader = TimedReadline(proc.stderr.fileno())

    try:
        # Read the output data
        line = line_reader(1)
        while line is not None:
            if line:
                base_log(line)

            # Check for timeout
            if time.time() - starttime > options.daemon_timeout and not term:
                shutdowntime = time.time()
                log("Timed out")
                log("Sending SIGTERM")
                term = True
                try:
                    os.kill(proc.pid, signal.SIGTERM)
                except OSError:
                    pass

            # Match record counts
            match = regexp.search(line)
            if match:
                count += 1
                # Reset the timer if we are still receiving data
                starttime = time.time()
                if count >= limit and not term:
                    shutdowntime = time.time()
                    log("Reached limit")
                    log("Sending SIGTERM")
                    term = True
                    try:
                        os.kill(proc.pid, signal.SIGTERM)
                    except OSError:
                        pass

            # Check for clean shutdown
            match = closing.search(line)
            if match:
                clean = True

            # Check for timeout on SIGTERM shutdown
            if shutdowntime and time.time() - shutdowntime > 15:
                log("Timeout on SIGTERM.  Sending SIGKILL")
                shutdowntime = None
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                except OSError:
                    pass

            # Get next line
            line = line_reader(1)

    finally:
        # Stop sending network data
        if send_list:
            stop_network_data(send_list)

        # Sleep briefly before polling for exit.
        time.sleep(1)
        proc.poll()
        if proc.returncode is None:
            log("Daemon has not exited.  Sending SIGKILL")
            try:
                os.kill(proc.pid, signal.SIGKILL)
            except OSError:
                pass

    # Print record count
    print("File count:", count)
    base_log("File count:", count)
    if limit != count:
        print(("ERROR: expecting %s files, got %s files" %
               (limit, count)))
        base_log(("ERROR: expecting %s files, got %s files" %
                  (limit, count)))

    # Check for clean exit
    if not clean:
        print("ERROR: shutdown was not clean")
        base_log("ERROR: shutdown was not clean")

    # Exit with the process's error code
    if proc.returncode is None:
        log("Exiting: Deamon did not appear to terminate normally")
        sys.exit(1)
    else:
        log("Exiting: Daemon returned", proc.returncode)
        sys.exit(proc.returncode)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except:
        traceback.print_exc(file=sys.stdout)
        if logfile:
            traceback.print_exc(file=logfile)
