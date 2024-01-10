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
# $SiLK: rwpollexec-daemon.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################
from __future__ import print_function
import optparse
import subprocess
import signal
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
    if logfile:
        string_write(logfile, out)
    if VERBOSE:
        sys.stderr.write(out)

def log(*args):
    out = "%s: %s:" % (time.asctime(), os.path.basename(sys.argv[0]))
    base_log(out, *args)

exit_sig_value = 255

def exit_sig(sig, frame):
    sys.exit(exit_sig_value)

def execute(args):
    global exit_sig_value
    if len(args) != 1:
        log("Requires a single file option in execute mode")
        sys.exit(255)
    lines = open(args[0], 'r').readlines()
    command = lines[0].strip()
    if command == "hang":
        for i in range(0, signal.NSIG):
            try:
                signal.signal(i, signal.SIG_IGN)
            except ValueError:
                pass
            except RuntimeError:
                pass
            except OSError:
                # In Python 3.3, signal.signal() raises OSError
                # instead of RuntimeError
                pass
        while True:
            signal.pause()
    elif command == "term":
        val = int(lines[1])
        exit_sig_value = val
        signal.signal(signal.SIGTERM, exit_sig)
        while True:
            signal.pause()
    elif command == "return":
        val = int(lines[1])
        sys.exit(val)
    elif command == "signal":
        val = int(lines[1])
        os.kill(os.getpid(), val)
    else:
        sys.exit(255)

def handle_file_op(option, opt_str, value, parser, *args, **kwds):
    if value == None:
        value = "0"
    else:
        value = str(value)
    if opt_str == "--hang":
        parser.values.infile.append(("hang",""))
    elif opt_str == "--term":
        parser.values.infile.append(("term", value))
    elif opt_str == "--return":
        parser.values.infile.append(("return", value))
    elif opt_str == "--signal":
        parser.values.infile.append(("signal", value))
    else:
        sys.exit(255)

def create_files(dirobj, spec):
    i = 0
    for (item, value) in spec:
        name = "%0d" % (i,)
        i += 1
        loc = os.path.join(dirobj.dirname['incoming'], name)
        f = open(loc, 'w')
        f.writelines((item, '\n', value, '\n'))
        f.close()

def main():
    global VERBOSE
    global logfile
    parser = optparse.OptionParser()
    parser.set_defaults(infile=[])
    parser.add_option("--hang", action="callback", callback=handle_file_op)
    parser.add_option("--term", action="callback", type="int",
                      callback=handle_file_op)
    parser.add_option("--return", action="callback", type="int",
                      callback=handle_file_op)
    parser.add_option("--signal", action="callback", type="int",
                      callback=handle_file_op)
    parser.add_option("--exec", action="store_true", dest="execute",
                      default=False)
    parser.add_option("--basedir", action="store", type="string",
                      dest="basedir")
    parser.add_option("--no-archive", action="store_true", dest="no_archive",
                      default=False)
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

    if options.execute:
        execute(args)           # Does not return


    # Create the dirs
    dirobj = Dirobject(overwrite=options.overwrite, basedir=options.basedir)
    dirobj.dirs = ['incoming', 'archive', 'error', 'log']
    dirobj.create_dirs()

    # Make the log file
    logfile = open(dirobj.get_path('log', 'rwpollexec-daemon.log'), 'wb', 0)

    # Generate the subprocess arguments
    args += ['--log-dest', 'stderr',
             '--log-level', options.log_level,
             '--no-daemon',
             '--incoming-directory', dirobj.dirname['incoming'],
             '--error-directory', dirobj.dirname['error']]
    if not options.no_archive:
        args += ['--archive-directory', dirobj.dirname['archive']]

    progname = os.environ.get("RWPOLLEXEC",
                              os.path.join('.', 'rwpollexec'))
    args = progname.split() + args

    # Set up state variables
    run_count = 0
    complete_count = 0
    success_count = 0
    nonzero_count = 0
    killed_count = 0
    clean = False
    term = False
    limit = len(options.infile)
    regexp = re.compile("Running \[\d+\]:")
    success = "Command .* has completed successfully"
    nonzero = "Command .* has completed with a nonzero return"
    killed = "Command .* was terminated by SIG"
    complete = re.compile("(?P<success>%s)|(?P<nonzero>%s)|(?P<killed>%s)" %
                          (success, nonzero, killed))
    closing = re.compile("Stopped logging")

    if limit == 0:
        parser.print_usage()
        sys.exit(255)

    # Create data
    create_files(dirobj, options.infile)

    # Note the time
    starttime = time.time()
    shutdowntime = None
    endedtime = None

    # Start the process
    log("Running", "'%s'" % "' '".join(args))
    proc = subprocess.Popen(args, stderr=subprocess.PIPE,
                            preexec_fn=lambda:os.setpgid(0, 0))
    try:
        os.setpgid(proc.pid, 0)
    except OSError:
        pass
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

            # Match running counts
            match = regexp.search(line)
            if match:
                run_count += 1
                # Reset the timer if we are still receiving data
                starttime = time.time()

            # Match success counts
            match = complete.search(line)
            if match:
                if match.group('success') is not None:
                    success_count += 1
                elif match.group('nonzero') is not None:
                    nonzero_count += 1
                elif match.group('killed') is not None:
                    killed_count += 1
                complete_count += 1
                # Reset the timer if we are still receiving data
                starttime = time.time()
                if complete_count >= limit and not term:
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
                    os.killpg(proc.pid, signal.SIGKILL)
                    break
                except OSError:
                    pass

            # Check to see if the process has ended
            if endedtime is None:
                proc.poll()
                if proc.returncode is not None:
                    endedtime = time.time()

            # Allow some time after the process has ended for any
            # remaining output the be handled
            if endedtime and time.time() - endedtime > 5:
                break

            # Get next line
            line = line_reader(1)

    finally:
        # Sleep briefly before polling for exit.
        time.sleep(1)
        proc.poll()
        if proc.returncode is None:
            log("Daemon has not exited.  Sending SIGKILL")
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass

    # Kill everything for good luck
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass

    # Print record count
    print("Run count:", run_count)
    print(("Complete count (success, failure): (%s, %s) = %s" %
           (success_count, nonzero_count + killed_count, complete_count)))
    base_log("Run count:", run_count)
    base_log(("Complete count (success, failure): (%s, %s) = %s" %
              (success_count, nonzero_count + killed_count, complete_count)))
    if limit != complete_count:
        print(("ERROR: expecting %s files, got %s files" %
               (limit, complete_count)))
        base_log(("ERROR: expecting %s files, got %s files" %
                  (limit, complete_count)))

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
