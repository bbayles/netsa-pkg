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
# $SiLK: daemon_test.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################
from __future__ import print_function
import numbers
import os
import os.path
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import tempfile
import threading

from config_vars import config_vars


#V5PDU_LEN  = 1464
TCPBUF     = 2048
LINEBUF    = 1024

if sys.version_info[0] >= 3:
    coding = {"encoding": "latin_1"}
else:
    coding = {}

def string_write(f, s):
    return f.write(bytes(s, **coding))

class TimedReadline(object):
    def __init__(self, fd):
        self.buf = ""
        if isinstance(fd, numbers.Integral):
            self.fd = fd
        else:
            self.fd = fd.fileno()

    def __call__(self, timeout):
        while True:
            x = self.buf.find('\n')
            if x >= 0:
                retval = self.buf[:x+1]
                self.buf = self.buf[x+1:]
                return retval
            (r, w, x) = select.select([self.fd], [], [], timeout)
            if r:
                more = os.read(self.fd, LINEBUF)
                if more:
                    self.buf += more.decode('latin_1')
                else:
                    return None
            else:
                return ""

class Dirobject(object):

    def __init__(self, overwrite=False, basedir=None):
        self.dirs = list()
        self.dirname = dict()
        self.basedir = basedir
        self.dirs_created = False
        self.overwrite = overwrite

    def create_basedir(self):
        if self.basedir:
            if not os.path.exists(self.basedir):
                os.mkdir(self.basedir)
        else:
            self.basedir = tempfile.mkdtemp()

    def remove_basedir(self):
        if self.basedir and self.dirs_created:
            shutil.rmtree(self.basedir)
            self.dirs_created = False

    def create_dirs(self):
        if not self.dirs_created:
            self.create_basedir()
            for name in self.dirs:
                self.dirname[name] = os.path.abspath(
                    os.path.join(self.basedir, name))
                if os.path.exists(self.dirname[name]):
                    if self.overwrite:
                        shutil.rmtree(self.dirname[name])
                        os.mkdir(self.dirname[name])
                else:
                    os.mkdir(self.dirname[name])
            self.dirs_created = True

    def get_path(self, name, path):
        return os.path.join(self.dirname[name], path)


class PduSender(object):
    def __init__(self, max_recs, port, log, address="localhost"):
        self._port = port
        self._max_recs = max_recs
        self._log = log
        self._address = ("[%s]" % address)
        self.process = None

    def start(self):
        prog = os.path.join(os.environ["top_srcdir"], "tests", "make-data.pl")
        args = [config_vars["PERL"], prog,
                "--pdu-network", self._address + ":" + str(self._port),
                "--max-records", str(self._max_recs)]
        self._log("Starting: %s" % args)
        self.process = subprocess.Popen(args)
        return self.process

    def stop(self):
        if self.process is None:
            return None
        self.process.poll()
        if self.process.returncode is None:
            try:
                os.kill(self.process.pid, signal.SIGTERM)
            except OSError:
                pass
        return self.process.returncode


class TcpSender(object):
    def __init__(self, file, port, log, address="localhost"):
        self._file = file
        self._port = port
        self._log = log
        self._address = address
        self._running = False

    def start(self):
        thread = threading.Thread(target = self.go)
        thread.daemon = True
        thread.start()

    def go(self):
        self._running = True
        sock = None
        # Try each address until we connect to one; no need to report
        # errors here
        for res in socket.getaddrinfo(self._address, self._port,
                                      socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
            except socket.error:
                sock = None
                continue
            try:
                sock.connect(sa)
            except socket.error:
                sock.close()
                sock = None
                continue
            break
        if sock is None:
            self._log("Could not open connection to [%s]:%d" %
                      (self._address, self._port))
            sys.exit(1)
        self._log("Connected to [%s]:%d" % (self._address, self._port))
        sock.settimeout(1)
        # Send the data
        while self._running:
            pdu = self._file.read(TCPBUF)
            if not pdu:
                self._running = False
                continue
            count = len(pdu)
            while self._running and count:
                try:
                    num_sent = sock.send(pdu)
                    pdu = pdu[num_sent:]
                    count -= num_sent
                except socket.timeout:
                    pass
                except socket.error as msg:
                    if isinstance(msg, tuple):
                        errmsg = msg[1]
                    else:
                        errmsg = msg
                    self._log("Error sending to [%s]:%d: %s" %
                              (self._address, self._port, errmsg))
                    self._running = False
        # Done
        sock.close()

    def stop(self):
        self._running = False


class UdpSender(object):
    def __init__(self, file, port, log, address="localhost"):
        self._file = file
        self._port = port
        self._log = log
        self._address = address
        self._running = False

    def start(self):
        thread = threading.Thread(target = self.go)
        thread.daemon = True
        thread.start()

    def go(self):
        # Some log messages helpful for debugging are commented with "#|"
        #
        self._running = True
        sock = None
        # Try each address until we connect to one; no need to report
        # errors here
        for res in socket.getaddrinfo(self._address, self._port,
                                      socket.AF_UNSPEC, socket.SOCK_DGRAM):
            af, socktype, proto, canonname, sa = res
            try:
                sock = socket.socket(af, socktype, proto)
            except socket.error:
                sock = None
                continue
            try:
                sock.connect(sa)
            except socket.error:
                sock.close()
                sock = None
                continue
            break
        if sock is None:
            self._log("Could not open connection to [%s]:%d" %
                      (self._address, self._port))
            sys.exit(1)
        self._log("Connected to [%s]:%d" % (self._address, self._port))
        # seconds to sleep after sending a packet
        sleeptime = 0.000200
        # the loopback MTU
        MTU = 4096
        # mapping from Template IDs to lengths
        tidtolength = {
            0x9dd0 : 48,
            0x9dd1 : 56,
            0x9dd2 : 56,
            0x9dd3 : 56,
            0x9dd4 : 56,
            0x9ed0 : 88,
            0x9ed1 : 88,
            0x9ed2 : 88,
            0x9ed3 : 88,
            0x9ed4 : 96,
            # Template from SiLK 3.11.0 and earlier
            0xafea : 120
        }
        # parsing an IPFIX msg header
        hdrstruct = struct.Struct("!HHIII")
        hdrlen = hdrstruct.size
        # parsing an IPFIX set header
        setstruct = struct.Struct("!HH")
        setlen = setstruct.size
        # to update the sequence number in a header
        seqnumstruct = struct.Struct("!I")
        # number of records, for handling sequence number
        reccount = 0
        while self._running:
            hdr = self._file.read(hdrlen)
            if len(hdr) != hdrlen:
                self._running = False
                continue
            (vers, octets, exptime, count, domain) = hdrstruct.unpack(hdr)
            #|self._log("Read a msg hdr ver=%d, oct=%d, tim=%d, cnt=%d, dom=%d"
            #|          % (vers, octets, exptime, count, domain))
            if vers != 10 or octets < hdrlen:
                self._running = False
                self._log("Bad IPFIX version (%d) or length (%d)" %
                          (vers, octets))
                continue
            msg = self._file.read(octets - hdrlen)
            if len(msg) != octets - hdrlen:
                self._log("Short read (expected %d, got %d)" %
                          (octets - hdrlen, len(msg)))
                self._running = False
                continue
            while self._running and len(msg) > setlen:
                # get next set from the message
                (id, sz) = setstruct.unpack(msg[0:setlen])
                #|self._log("Got set id=%d, sz=%d, remaing msg = %d" %
                #|          (id, sz, len(msg) - sz))
                if sz < setlen:
                    self._log("Bad set length %d, id was %d" % (sz, id))
                    msg = ""
                    continue
                setdata = msg[0:sz]
                msg = msg[sz:]
                # build the new single-set message
                mysize = hdrlen + sz
                if mysize > MTU:
                    self._log("Not sending large packet (%d octets)" % mysize)
                    continue
                hdr = hdrstruct.pack(vers, mysize, exptime, reccount, domain)
                #|self._log("Sending msg ver=%d, oct=%d, tim=%d, cnt=%d, dom=%d"
                #|          % (vers, mysize, exptime, reccount, domain))
                # update record count
                if id >= 256:
                    try:
                        reclen = tidtolength[id]
                        reccount = reccount + int((sz - setlen) / reclen)
                    except KeyError:
                        self._log("Set uses unknown id %d" % id)
                # send it
                try:
                    sock.send(hdr + setdata)
                except socket.error as err:
                    if isinstance(err, tuple):
                        errmsg = err[1]
                    else:
                        errmsg = err
                    self._log("Error sending to [%s]:%d: %s" %
                              (self._address, self._port, errmsg))
                time.sleep(sleeptime)
            #|self._log("At end of message, count = %d, reccount = %d" %
            #|          (count, reccount))
        # Done
        sock.close()

    def stop(self):
        self._running = False


def get_ephemeral_port():
    sock = socket.socket()
    sock.bind(("", 0))
    (addr, port) = sock.getsockname()
    sock.close()
    return port
