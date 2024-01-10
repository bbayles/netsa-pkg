#!/usr/bin/env python
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
# $SiLK: sendrcv_tests.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

import sys
import re
import os
import os.path
import tempfile
import random
import stat
import fcntl
import re
import shutil
import itertools
import optparse
import time
import signal
import select
import subprocess
import socket
import json
import traceback
import struct
import datetime

conv = json

srcdir = os.environ.get("srcdir")
if srcdir:
    sys.path.insert(0, os.path.join(srcdir, "tests"))
from gencerts import reset_all_certs_and_keys, generate_signed_cert, generate_ca_cert, PASSWORD
from config_vars import config_vars
from daemon_test import get_ephemeral_port, Dirobject

os.environ["RWSENDER_TLS_PASSWORD"] = PASSWORD
os.environ["RWRECEIVER_TLS_PASSWORD"] = PASSWORD

try:
    import hashlib
    md5_new = hashlib.md5
    sha1_new = hashlib.sha1
except ImportError:
    import md5
    md5_new = md5.new
    import sha
    sha1_new = sha.new


global_int     = 0

KILL_DELAY     = 20
CHUNKSIZE      = 2048
OVERWRITE      = False
LOG_LEVEL      = "info"
LOG_OUTPUT     = []

# do not remove the directory after the test
NO_REMOVE      = False
FILE_LIST_FILE = None

# tests to run (in the order in which to run them) if no tests are
# specified on the command line
ALL_TESTS = ['testConnectOnlyIPv4Addr', 'testConnectOnlyHostname',
             'testConnectOnlyTLS', 'testConnectOnlyIPv6Addr',
             'testSendRcvStopReceiverServer', 'testSendRcvStopSenderServer',
             'testSendRcvStopReceiverClient', 'testSendRcvStopSenderClient',
             'testSendRcvKillReceiverServer', 'testSendRcvKillSenderServer',
             'testSendRcvKillReceiverClient', 'testSendRcvKillSenderClient',
             'testSendRcvStopReceiverServerTLS',
             'testSendRcvStopSenderServerTLS',
             'testSendRcvStopReceiverClientTLS',
             'testSendRcvStopSenderClientTLS',
             'testSendRcvKillReceiverServerTLS',
             'testSendRcvKillSenderServerTLS',
             'testSendRcvKillReceiverClientTLS',
             'testSendRcvKillSenderClientTLS',
             'testMultiple', 'testMultipleTLS',
             'testFilter', 'testPostCommand']

rfiles = None

TIMEOUT_FACTOR = 1.0


if sys.version_info[0] >= 3:
    coding = {"encoding": "ascii"}
else:
    coding = {}


class TriggerError(Exception):
    pass

class FileTransferError(Exception):
    pass

def global_log(name, msg, timestamp=True):
    if not name:
        name = sys.argv[0]
    out = name + ": "
    if timestamp:
        out += datetime.datetime.now().strftime("%b %d %H:%M:%S ")
    out += msg
    if out[-1] != "\n":
        out += "\n"
    for dest in LOG_OUTPUT:
        dest.write(out)
        dest.flush()

def t(dur):
    return int(dur * TIMEOUT_FACTOR)

def setup():
    global rfiles
    rfiles = []
    top_tests = os.path.dirname(FILE_LIST_FILE)
    file_list = open(FILE_LIST_FILE, "r", 1)
    for line in file_list:
        (path, size, md5) = line.split()
        path = os.path.join(top_tests, path)
        # empty string is placeholder for SHA1 digest
        rfiles.append((path, (int(size), "", md5)))

def teardown():
    pass

def tls_supported():
    return eval(config_vars.get('SK_ENABLE_GNUTLS', None))

def ipv6_supported():
    return eval(config_vars.get('SK_ENABLE_INET6_NETWORKING', None))

trigger_id = 0

def trigger(*specs, **kwd):
    global trigger_id
    trigger_id += 1
    pid = kwd.get('pid', True)
    first = kwd.get('first', False)
    pipes = {}
    count = len(specs)
    retval = []
    for daemon, timeout, match in specs:
        daemon.dump(('trigger',
                     {'pid': pid, 'id': trigger_id,
                      'match': match, 'timeout': t(timeout)}))
        pipes[daemon.pipe] = (daemon, timeout, match, len(retval))
        retval.append(None)
    while count:
        (readers, writers, x) = select.select(pipes.keys(), [], [])
        for reader in readers:
            data = pipes[reader]
            try:
                rv = data[0].load()
            except EOFError:
                raise TriggerError(data[:3])
            if rv[0] != 'trigger':
                # Trigger failed
                raise TriggerError(data[:3])
            if rv[1] != trigger_id:
                continue
            if rv[2] == False:
                raise TriggerError(data[:3])
            count -= 1
            retval[data[3]] = rv[3]
            del pipes[reader]
            if first:
                return retval
    return retval

def check_started(clients, servers, tls):
    if tls:
        tcp_tls = r"\(TCP, TLS\)"
        timeout = 120
    else:
        tcp_tls = r"\(TCP\)"
        timeout = 10
    watches = itertools.chain(
        ((c, timeout, r"Attempting to connect to \S+ %s" % tcp_tls)
         for c in clients),
        ((s, timeout, r"Bound to \S+ for listening %s" % tcp_tls)
         for s in servers))
    trigger(*watches)

def check_connected(clients, servers, timeout=25):
    if sys.version_info[0] < 3:
        zipper = itertools.izip_longest
    else:
        zipper = itertools.zip_longest
    for c,s in zipper(clients, servers):
        watches = []
        if c is not None:
            watches = watches + [
                (s, timeout, "Connected to remote %s" % c.name) for s in servers
            ]
        if s is not None:
            watches = watches + [
                (c, timeout, "Connected to remote %s" % s.name) for c in clients
            ]
        trigger(*watches)

def create_random_file(suffix="", prefix="random", dir=None, size=(0, 0)):
    (handle, path) = tempfile.mkstemp(suffix, prefix, dir)
    f = os.fdopen(handle, "w")
    numbytes = random.randint(size[0], size[1])
    totalbytes = numbytes
    #checksum_sha = sha1_new()
    checksum_md5 = md5_new()
    while numbytes:
        length = min(numbytes, CHUNKSIZE)
        try:
            bytes = os.urandom(length)
        except NotImplementedError:
            bytes = ''.join(chr(random.getrandbits(8))
                            for x in range(0, length))
        f.write(bytes)
        #checksum_sha.update(bytes)
        checksum_md5.update(bytes)
        numbytes -= length
    f.close()
    # empty string is placeholder for SHA1 digest
    return (path, (totalbytes, "", checksum_md5.hexdigest()))

def checksum_file(path):
    f = open(path, 'rb')
    #checksum_sha = sha1_new()
    checksum_md5 = md5_new()
    size = os.fstat(f.fileno())[stat.ST_SIZE]
    data = f.read(CHUNKSIZE)
    while data:
        #checksum_sha.update(data)
        checksum_md5.update(data)
        data = f.read(CHUNKSIZE)
    f.close()
    # empty string is placeholder for SHA1 digest
    return (size, "", checksum_md5.hexdigest())


sconv = "L"
slen  = struct.calcsize(sconv)


class Daemon(Dirobject):

    def __init__(self, name=None, log_level="info", prog_env=None,
                 verbose=True, **kwds):
        global global_int
        Dirobject.__init__(self, **kwds)
        if name:
            self.name = name
        else:
            self.name = type(self).__name__ + str(global_int)
            global_int += 1
        self.process = None
        self.logdata = []
        self.log_level = log_level
        self._prog_env = prog_env
        self.daemon = True
        self.verbose = verbose
        self.pipe = None
        self.pid = None
        self.trigger = None
        self.timeout = None
        self.channels = []
        self.pending_line = None

    def printv(self, *args):
        if self.pid is None or self.pid != 0:
            me = "parent"
        else:
            me = "child"
        if self.verbose:
            global_log(self.name, me + ("[%s]:" % os.getpid()) +
                       ' '.join(str(x) for x in args))

    def get_executable(self):
        return os.environ.get(self._prog_env,
                              os.path.join(".", self.exe_name))

    def get_args(self):
        args = self.get_executable().split()
        args.extend([ '--no-daemon',
                      '--log-dest', 'stderr',
                      '--log-level', self.log_level])
        return args

    def init(self):
        pass

    def log_verbose(self, msg):
        if self.verbose:
            global_log(self.name, msg)

    def _handle_log(self, fd):
        # 'fd' is the log of the process, which supports non-blocking
        # reads.  read from the log until there is thing left to read,
        # so that select() on 'fd' will work correctly
        got_line = False
        try:
            # when no-more-data, following returns empty string in
            # Python3, but throws IOError [EAGAIN] in Python2
            for line in fd:
                line = str(line, **coding)
                # handle reading a partial line last time and this time
                if self.pending_line:
                    line = self.pending_line + line
                    self.pending_line = None
                if line[-1] != "\n":
                    self.pending_line = line
                    break
                got_line = True
                self.logdata.append(line)
                global_log(self.name, line, timestamp=False)
                if self.trigger:
                    match = self.trigger['re'].search(line)
                    if match:
                        self.log_verbose(
                            'Trigger fired for "%s"' % self.trigger['match'])
                        self.dump(('trigger', self.trigger['id'], True, line))
                        self.timeout = None
                        self.trigger = None
        except IOError:
            pass
        if not got_line:
            return False
        return True

    def _handle_parent(self):
        retval = False
        request = self.load()
        # self.log_verbose("Handling %s" % request)
        if request[0] == 'stop':
            self._stop()
        if request[0] == 'start':
            if self.process is not None:
                self.process.poll()
                if self.process.returncode is None:
                    raise RuntimeError()
            self._start()
        elif request[0] == 'kill':
            self._kill()
        elif request[0] == 'end':
            self._end()
            self.dump(("stopped", self.process.returncode))
        elif request[0] == 'exit':
            try:
                self.pipe.close()
            except:
                pass
            os._exit(0)
        elif request[0] == 'trigger':
            # search previously captured output from the application
            self.trigger = request[1]
            if self.trigger['pid']:
                regexp = re.compile(r"\[%s\].*%s" %
                                    (self.process.pid, self.trigger['match']))
            else:
                regexp = re.compile(self.trigger['match'])
            for line in self.logdata:
                match = regexp.search(line)
                if match:
                    self.log_verbose(
                        'Trigger fired for "%s"' % self.trigger['match'])
                    self.dump(('trigger', self.trigger['id'], True, line))
                    self.trigger = None
                    return retval
            self.trigger['re'] = regexp
            self.timeout = time.time() + self.trigger['timeout']
        return retval

    def _child(self):
        while self.channels:
            # channels contains a socket to the parent and to the
            # stderr of the application's process
            (readers, writers, x) = select.select(self.channels, [], [], 1)
            if self.process is not None and self.process.stderr in readers:
                rv = self._handle_log(self.process.stderr)
                if not rv:
                    self.channels.remove(self.process.stderr)
            if self.pipe in readers:
                if self._handle_parent():
                    try:
                        self.pipe.close()
                    except:
                        pass
                    self.channels.remove(self.pipe)
            if self.timeout is not None and time.time() > self.timeout:
                self.log_verbose(
                    'Trigger timed out after %s seconds: "%s"' %
                    (self.trigger['timeout'], self.trigger['match']))
                self.dump(('trigger', self.trigger['id'], False))
                self.timeout = None
                self.trigger = None

    def expect(self, cmd):
        try:
            while True:
                rv = self.load()
                # self.log_verbose("Retrieved %s" % rv)
                if cmd == rv[0]:
                    break
            return rv
        except EOFError:
            if cmd in ['stop', 'kill', 'end']:
                return ('stopped', None)
            raise

    def start(self):
        if self.pid is not None:
            self.dump(('start',))
            self.expect('start')
            return None
        pipes = socket.socketpair()
        self.pid = os.fork()
        if self.pid != 0:
            pipes[1].close()
            self.pipe = pipes[0]
            self.dump(('start',))
            self.expect('start')
            return None
        try:
            pipes[0].close()
            self.pipe = pipes[1]
            self.channels = [self.pipe]
            self._child()
        except:
            traceback.print_exc()
            self._kill()
        finally:
            try:
                self.pipe.close()
            except:
                pass
            os._exit(0)

    def _start(self):
        if self.process is not None and self.process.stderr in self.channels:
            self.channels.remove(self.process.stderr)
        # work around issue #11459 in python 3.1.[0-3], 3.2.0 (where a
        # process is line buffered despite bufsize=0) by making the
        # buffer large, making the stream non-blocking, and getting
        # everything available from the stream when we read
        self.process = subprocess.Popen(self.get_args(), bufsize = -1,
                                        stderr=subprocess.PIPE)
        fcntl.fcntl(self.process.stderr, fcntl.F_SETFL,
                    (os.O_NONBLOCK
                     | fcntl.fcntl(self.process.stderr, fcntl.F_GETFL)))
        self.channels.append(self.process.stderr)
        self.dump(('start',))

    def dump(self, arg):
        value = conv.dumps(arg).encode('ascii')
        data = struct.pack(sconv, len(value)) + value
        try:
            self.pipe.sendall(data)
        except IOError:
            pass

    def load(self):
        rv = self.pipe.recv(slen)
        if len(rv) != slen:
            raise RuntimeError
        (length,) = struct.unpack(sconv, rv)
        value = b""
        while len(value) != length:
            value += self.pipe.recv(length)
        retval = conv.loads(value.decode('ascii'))
        return retval

    def kill(self):
        if self.pid is None:
            return None
        self.dump(('kill',))
        self.expect('kill')

    def stop(self):
        if self.pid is None:
            return None
        self.dump(('stop',))
        self.expect('stop')

    def end(self):
        if self.pid is None:
            return None
        self.dump(('end',))
        rv = self.expect('stopped')[1]
        if rv is not None:
            if rv >= 0:
                self.log_verbose("Exited with status %s" % rv)
            else:
                self.log_verbose("Exited with signal %s" % (-rv))
        return rv

    def exit(self):
        self.end()
        if self.pid is None:
            return None
        self.dump(('exit',))
        try:
            os.waitpid(self.pid, 0)
        except OSError:
            pass

    def _kill(self):
        if self.process is not None and self.process.returncode is None:
            try:
                self.log_verbose("Sending SIGKILL")
                os.kill(self.process.pid, signal.SIGKILL)
            except OSError:
                pass
        self.dump(('kill',))

    def _stop(self):
        if self.process is not None and self.process.returncode is None:
            try:
                self.log_verbose("Sending SIGTERM")
                os.kill(self.process.pid, signal.SIGTERM)
            except OSError:
                pass
        self.dump(('stop',))

    def _end(self):
        target = time.time() + KILL_DELAY
        self.process.poll()
        while self.process.returncode is None and time.time() < target:
            self.process.poll()
            time.sleep(1)
        if self.process.returncode is not None:
            while self._handle_log(self.process.stderr):
                pass
            return True
        self._kill()
        self.process.poll()
        while self.process.returncode is None:
            self.process.poll()
            time.sleep(1)
        while self._handle_log(self.process.stderr):
            pass
        return False


class Sndrcv_base(Daemon):

    def __init__(self, name=None, **kwds):
        Daemon.__init__(self, name, **kwds)
        self.mode = "client"
        self.listen = None
        self.port = None
        self.clients = list()
        self.servers = list()
        self.ca_cert = None
        self.ca_key = None
        self.cert = None

    def create_cert(self):
        self.cert = generate_signed_cert(self.basedir,
                                         (self.ca_key, self.ca_cert),
                                         os.path.join(self.basedir, "key.pem"),
                                         os.path.join(self.basedir, "key.p12"))

    def set_ca(self, ca_key, ca_cert):
        self.ca_key = ca_key
        self.ca_cert = ca_cert

    def init(self):
        Daemon.init(self)
        if self.ca_cert:
            self.dirs.append("cert")
        self.create_dirs()
        if self.ca_cert:
            self.create_cert()

    def get_args(self):
        args = Daemon.get_args(self)
        args += ['--mode', self.mode,
                 '--identifier', self.name]
        if self.ca_cert:
            args += ['--tls-ca', os.path.abspath(self.ca_cert),
                     '--tls-pkcs12', os.path.abspath(self.cert),
                     '--tls-priority=NORMAL',
                     #'--tls-priority=SECURE128:+SECURE192:-VERS-ALL:+VERS-TLS1.2',
                     #'--tls-security=ultra',
                     '--tls-debug-level=0']
        if self.mode == "server":
            if self.listen is not None:
                args += ['--server-port', "%s:%s" % (self.listen, self.port)]
            else:
                args += ['--server-port', str(self.port)]
            for client in self.clients:
                 args += ['--client-ident', client]
        else:
            for (ident, addr, port) in self.servers:
                args += ['--server-address',
                         ':'.join((ident, addr, str(port)))]
        return args

    def _check_file(self, dir, finfo):
        (path, (size, ck_sha, ck_md5)) = finfo
        path = os.path.join(self.dirname[dir], os.path.basename(path))
        if not os.path.exists(path):
            return ("Does not exist", path)
        (nsize, ck2_sha, ck2_md5) = checksum_file(path)
        if nsize != size:
            return ("Size mismatch (%s != %s)" % (size, nsize), path)
        if ck2_sha != ck_sha:
            return ("SHA mismatch (%s != %s)" % (ck_sha, ck2_sha), path)
        if ck2_md5 != ck_md5:
            return ("MD5 mismatch (%s != %s)" % (ck_md5, ck2_md5), path)
        return (None, path)


class Rwsender(Sndrcv_base):

    def __init__(self, name=None, polling_interval=5, filters=[],
                 overwrite=None, log_level=None, **kwds):
        if log_level is None:
            log_level = LOG_LEVEL
        if overwrite is None:
            overwrite = OVERWRITE
        Sndrcv_base.__init__(self, name, overwrite=overwrite,
                             log_level=log_level, prog_env="RWSENDER", **kwds)
        self.exe_name = "rwsender"
        self.filters = filters
        self.polling_interval = polling_interval
        self.dirs = ["in", "proc", "error"]

    def get_args(self):
        args = Sndrcv_base.get_args(self)
        args += ['--incoming-directory', os.path.abspath(self.dirname["in"]),
                 '--processing-directory',
                 os.path.abspath(self.dirname["proc"]),
                 '--error-directory', os.path.abspath(self.dirname["error"]),
                 '--polling-interval', str(self.polling_interval)]
        for ident, regexp in self.filters:
            args.extend(["--filter", ident + ':' + regexp])
        return args

    def send_random_file(self, suffix="", prefix="random", size=(0, 0)):
        return create_random_file(suffix = suffix, prefix = prefix,
                                  dir = self.dirname["in"], size = size)

    def send_files(self, files):
        for f, data in files:
            shutil.copy(f, self.dirname["in"])

    def check_error(self, data):
        return self._check_file("error", data)


class Rwreceiver(Sndrcv_base):

    def __init__(self, name=None, post_command=None,
                 overwrite=None, log_level=None, **kwds):
        if log_level is None:
            log_level = LOG_LEVEL
        if overwrite is None:
            overwrite = OVERWRITE
        Sndrcv_base.__init__(self, name, overwrite=overwrite,
                             log_level=log_level, prog_env="RWRECEIVER", **kwds)
        self.exe_name = "rwreceiver"
        self.dirs = ["dest"]
        self.post_command = post_command

    def get_args(self):
        args = Sndrcv_base.get_args(self)
        args += ['--destination-directory',
                 os.path.abspath(self.dirname["dest"])]
        if self.post_command:
            args += ['--post-command', self.post_command]
        return args

    def check_sent(self, data):
        return self._check_file("dest", data)

class System(Dirobject):

    def __init__(self):
        Dirobject.__init__(self)
        self.create_dirs()
        self.client_type = None
        self.server_type = None
        self.clients = set()
        self.servers = set()
        self.ca_cert = None
        self.ca_key = None

    def create_ca_cert(self):
        self.ca_key, self.ca_cert = generate_ca_cert(
            self.basedir, os.path.join(self.basedir, 'ca_cert.pem'))

    def connect(self, clients, servers, tls=False, hostname=None):
        if tls:
            self.create_ca_cert()
        if hostname is None:
            hostname = os.environ.get("SK_TESTS_SENDRCV_HOSTNAME")
            if hostname is None:
                hostname = "localhost"
        if isinstance(clients, Sndrcv_base):
            clients = [clients]
        if isinstance(servers, Sndrcv_base):
            servers = [servers]
        for server in servers:
            server.listen = hostname
        for client in clients:
            for server in servers:
                self._connect(client, server, tls, hostname)

    def _connect(self, client, server, tls, hostname):
        if not isinstance(client, Sndrcv_base):
            raise ValueError("Can only connect rwsenders and rwreceivers")
        if not self.client_type:
            if isinstance(client, Rwsender):
                self.client_type = Rwsender
                self.server_type = Rwreceiver
            else:
                self.client_type = Rwreceiver
                self.server_type = Rwsender
        if not isinstance(client, self.client_type):
            raise ValueError("Client must be of type %s" %
                               self.client_type.__name__)
        if not isinstance(server, self.server_type):
            raise ValueError("Server must be of type %s" %
                               self.server_type.__name__)
        client.mode = "client"
        server.mode = "server"

        if server.port is None:
            server.port = get_ephemeral_port()

        client.servers.append((server.name, hostname, server.port))
        server.clients.append(client.name)

        self.clients.add(client)
        self.servers.add(server)

        if tls:
            client.set_ca(self.ca_key, self.ca_cert)
            server.set_ca(self.ca_key, self.ca_cert)

    def _forall(self, call, which, *args, **kwds):
        if which == "clients":
            it = self.clients
        elif which == "servers":
            it = self.servers
        else:
            it = itertools.chain(self.clients, self.servers)
        return [getattr(x, call)(*args, **kwds) for x in it]

    def start(self, which = None):
        self._forall("init", which)
        self._forall("start", which)

    def end(self, which = None, noremove=False):
        self._forall("exit", which)
        if not noremove:
            self.remove_basedir()

    def stop(self, which = None):
        self._forall("stop", which)


def _rename_pkcs12(x):
    if x == "--tls-pkcs12":
        return "--tls-cert"
    return x

# Like Rwsender but uses customized TLS keys+certificates
class RwsenderCert(Rwsender):
    def __init__(self, name, ca_cert, key, cert, **kwds):
        Rwsender.__init__(self, name, **kwds)
        self.ca_cert = ca_cert
        self.key = key
        self.cert = cert

    def create_cert(self):
        pass

    def set_ca(self, x, y):
        pass

    def get_args(self):
        args = Rwsender.get_args(self)
        if self.key:
            args += ['--tls-key', os.path.abspath(self.key)]
            return map(_rename_pkcs12, args)
        return args

# Like Rwreceiver but uses customized TLS keys+certificates
class RwreceiverCert(Rwreceiver):
    def __init__(self, name, ca_cert, key, cert, **kwds):
        Rwreceiver.__init__(self, name, **kwds)
        self.ca_cert = ca_cert
        self.key = key
        self.cert = cert

    def create_cert(self):
        pass

    def set_ca(self, x, y):
        pass

    def get_args(self):
        args = Rwreceiver.get_args(self)
        if self.key:
            args += ['--tls-key', os.path.abspath(self.key)]
            return map(_rename_pkcs12, args)
        return args

# Like System but uses customized TLS keys+certificates
class SystemCert(System):
    def __init__(self):
        System.__init__(self)

    def create_ca_cert(self):
        pass


#def Sender(**kwds):
#    return Rwsender(overwrite=OVERWRITE, log_level=LOG_LEVEL, **kwds)
#
#def Receiver(**kwds):
#    return Rwreceiver(overwrite=OVERWRITE, log_level=LOG_LEVEL, **kwds)

def _testConnectAndClose(tls=False, hostname="localhost"):
    if tls and not tls_supported():
        return None
    reset_all_certs_and_keys()
    s1 = Rwsender()
    r1 = Rwreceiver()
    sy = System()
    try:
        sy.connect(s1, r1, tls=tls, hostname=hostname)
        sy.start()
        check_started([s1], [r1], tls=tls)
        check_connected([r1], [s1])
        sy.stop()
        trigger((s1, 20, "Finished shutting down"),
                (r1, 20, "Finished shutting down"))
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)

def testConnectOnlyIPv4Addr():
    """
    Test to see if we can start a sender/receiver pair, that they
    connect, and that they shut down properly.
    """
    _testConnectAndClose(hostname="127.0.0.1")

def testConnectOnlyHostname():
    """
    Test to see if we can start a sender/receiver pair, that they
    connect, and that they shut down properly.
    """
    _testConnectAndClose()

def testConnectOnlyTLS():
    """
    Test to see if we can start a sender/receiver pair using TLS,
    that they connect, and that they shut down properly.
    """
    _testConnectAndClose(tls=True)

def testConnectOnlyIPv6Addr():
    """
    Test to see if we can start a sender/receiver pair, that they
    connect, and that they shut down properly.
    """
    if not ipv6_supported():
        return None
    _testConnectAndClose(hostname="[::1]")

def _testSendRcv(tls=False,
                 sender_client=True,
                 stop_sender=False,
                 kill=False):
    if tls and not tls_supported():
        return None
    global rfiles
    reset_all_certs_and_keys()
    s1 = Rwsender()
    r1 = Rwreceiver()
    if stop_sender:
        if kill:
            stop = s1.kill
        else:
            stop = s1.stop
        end = s1.end
        start = s1.start
        stopped = s1
    else:
        if kill:
            stop = r1.kill
        else:
            stop = r1.stop
        end = r1.end
        start = r1.start
        stopped = r1
    s1.create_dirs()
    s1.send_files(rfiles)
    sy = System()
    try:
        if sender_client:
            cli = s1
            srv = r1
        else:
            cli = r1
            srv = s1
        sy.connect(cli, srv, tls=tls)
        sy.start()
        check_started([cli], [srv], tls=tls)
        check_connected([cli], [srv], 75)
        trigger((s1, 40, "Succeeded sending .* to %s" % r1.name))
        stop()
        if not kill:
            trigger((stopped, 25, "Stopped logging"))
        end()
        start()
        if stopped == cli:
            check_started([cli], [], tls=tls)
        else:
            check_started([], [srv], tls=tls)
        check_connected([cli], [srv], 75)
        try:
            for path, data in rfiles:
                base = os.path.basename(path)
                data = {"name": re.escape(base),
                        "rname": r1.name, "sname": s1.name}
                trigger((s1, 40,
                         ("Succeeded sending .*/%(name)s to %(rname)s|"
                          "Remote side %(rname)s rejected .*/%(name)s")
                         % data),
                        (r1, 40,
                         "Finished receiving from %(sname)s: %(name)s" % data),
                        pid=False, first=True)
        except TriggerError:
            pass
        for f in rfiles:
            (error, path) = r1.check_sent(f)
            if error:
                global_log(False, ("Error receiving %s: %s" %
                                   (os.path.basename(f[0]), error)))
                raise FileTransferError()
        sy.stop()
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except KeyboardInterrupt:
        global_log(False, "%s: Interrupted by C-c", os.getpid())
        traceback.print_exc()
        sy.stop()
        raise
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)


def testSendRcvStopReceiverServer():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=False, kill=False)

def testSendRcvStopSenderServer():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=True, kill=False)

def testSendRcvStopReceiverClient():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    stopping the receiver.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=False, kill=False)

def testSendRcvStopSenderClient():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=True, kill=False)

def testSendRcvKillReceiverServer():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=False, kill=True)

def testSendRcvKillSenderServer():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=True, kill=True)

def testSendRcvKillReceiverClient():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    killing the receiver.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=False, kill=True)

def testSendRcvKillSenderClient():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=True, kill=True)


def testSendRcvStopReceiverServerTLS():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=False, kill=False, tls=True)

def testSendRcvStopSenderServerTLS():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=True, kill=False, tls=True)

def testSendRcvStopReceiverClientTLS():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    stopping the receiver.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=False, kill=False, tls=True)

def testSendRcvStopSenderClientTLS():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    stopping the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=True, kill=False, tls=True)

def testSendRcvKillReceiverServerTLS():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=False, kill=True, tls=True)

def testSendRcvKillSenderServerTLS():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=True, kill=True, tls=True)

def testSendRcvKillReceiverClientTLS():
    """
    Test a sender/receiver connection, with sender as server,
    sending files.  Midway the connection is terminated by
    killing the receiver.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=False, stop_sender=False, kill=True, tls=True)

def testSendRcvKillSenderClientTLS():
    """
    Test a sender/receiver connection, with receiver as server,
    sending files.  Midway the connection is terminated by
    killing the sender.  The connection is restarted and resumed.
    """
    _testSendRcv(sender_client=True, stop_sender=True, kill=True, tls=True)


def _testMultiple(tls=False):
    global rfiles
    if tls and not tls_supported():
        return None
    reset_all_certs_and_keys()
    s1 = Rwsender()
    s2 = Rwsender()
    r1 = Rwreceiver()
    r2 = Rwreceiver()
    sy = System()
    try:
        sy.connect([r1, r2], [s1, s2], tls=tls)
        sy.start()
        check_started([r1, r2], [s1, s2], tls=tls)
        check_connected([r1, r2], [s1, s2], timeout=70)

        filea = rfiles[0]
        fileb = rfiles[1]
        s1.send_files([filea])
        s2.send_files([fileb])
        params = {"filea": re.escape(os.path.basename(filea[0])),
                  "fileb": re.escape(os.path.basename(fileb[0])),
                  "rnamec": r1.name, "rnamed": r2.name}

        trigger((s1, 40,
                 "Succeeded sending .*/%(filea)s to %(rnamec)s" % params),
                (s2, 40,
                 "Succeeded sending .*/%(fileb)s to %(rnamec)s" % params))
        trigger((s1, 40,
                 "Succeeded sending .*/%(filea)s to %(rnamed)s" % params),
                (s2, 40,
                 "Succeeded sending .*/%(fileb)s to %(rnamed)s" % params))
        for f in [filea, fileb]:
            for r in [r1, r2]:
                (error, path) = r.check_sent(f)
                if error:
                    global_log(False, ("Error receiving %s: %s" %
                                       (os.path.basename(f[0]), error)))
                    raise FileTransferError()
        sy.stop()
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"),
                (s2, 25, "Stopped logging"),
                (r2, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)

def testMultiple():
    """
    Test two senders connected to two receivers.  Each sender
    sends a file to both receivers.
    """
    _testMultiple()

def testMultipleTLS():
    """
    Test two senders connected to two receivers via TLS.  Each
    sender sends a file to both receivers.
    """
    _testMultiple(tls=True)


def _testFilter(tls=False):
    global rfiles
    if tls and not tls_supported():
        return None
    reset_all_certs_and_keys()
    r1 = Rwreceiver()
    r2 = Rwreceiver()
    s1 = Rwsender(filters=[(r1.name, "[a-g]$"), (r2.name, "[d-j]$")])
    sy = System()
    try:
        sy.connect([r1, r2], s1, tls=tls)
        sy.start()
        check_started([r1, r2], [s1], tls=tls)
        check_connected([r1, r2], [s1], timeout=70)

        s1.send_files(rfiles)
        cfiles = [x for x in rfiles if 'a' <= x[0][-1] <= 'g']
        dfiles = [x for x in rfiles if 'd' <= x[0][-1] <= 'j']
        for (f, data) in cfiles:
            trigger((s1, 25,
                     "Succeeded sending .*/%(file)s to %(name)s"
                     % {"file": re.escape(os.path.basename(f)),
                        "name" : r1.name}))
        for (f, data) in dfiles:
            trigger((s1, 25,
                     "Succeeded sending .*/%(file)s to %(name)s"
                     % {"file": re.escape(os.path.basename(f)),
                        "name" : r2.name}))
        for f in cfiles:
            (error, path) = r1.check_sent(f)
            if error:
                global_log(False, ("Error receiving %s: %s" %
                                   (os.path.basename(f[0]), error)))
                raise FileTransferError()
        for f in dfiles:
            (error, path) = r2.check_sent(f)
            if error:
                global_log(False, ("Error receiving %s: %s" %
                                   (os.path.basename(f[0]), error)))
        cset = set(cfiles)
        dset = set(dfiles)
        for f in cset - dset:
            (error, path) = r2.check_sent(f)
            if not error:
                global_log(False, ("Unexpectedly received file %s" %
                                   os.path.basename(f[0])))
                raise FileTransferError()
        for f in dset - cset:
            (error, path) = r1.check_sent(f)
            if not error:
                global_log(False, ("Unexpectedly received file %s" %
                                   os.path.basename(f[0])))
                raise FileTransferError()
        sy.stop()
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"),
                (r2, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)

def testFilter():
    """
    Test filtering with a sender and two receivers.  Using
    filters, some files get sent to receiver A, some to receiver
    B, and some to both.
    """
    _testFilter()


def testPostCommand():
    """
    Test the post command option.
    """
    global rfiles
    if srcdir:
        cmddir = os.path.join(srcdir, "tests")
    else:
        cmddir = os.path.join(".", "tests")
    command = os.path.join(cmddir, "post-command.sh")
    post_command = command + " %I %s"
    if not os.access(command, os.X_OK):
        sys.exit(77)
    s1 = Rwsender()
    r1 = Rwreceiver(post_command=post_command)
    s1.create_dirs()
    s1.send_files(rfiles)
    sy = System()
    try:
        sy.connect(s1, r1)
        sy.start()
        check_connected([s1], [r1], timeout=70)
        for path, data in rfiles:
            trigger((r1, 40,
                     ("Post command: Ident: %(sname)s  "
                      "Filename: .*/%(file)s") %
                     {"file": re.escape(os.path.basename(path)),
                      "sname": s1.name}), pid=False)
        sy.stop()
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)


def _testFailedConnection(ca_cert, key, cert, hostname="127.0.0.1"):
    if not tls_supported():
        return None
    ca_cert = os.path.join(srcdir, "tests", ca_cert)
    key = os.path.join(srcdir, "tests", key)
    cert = os.path.join(srcdir, "tests", cert)
    s1 = RwsenderCert(None, ca_cert, key, cert)
    r1 = RwreceiverCert(None, ca_cert, key, cert)
    sy = SystemCert()
    try:
        sy.connect(s1, r1, tls=True, hostname=hostname)
        sy.start()
        check_started([s1], [r1], tls=True)
        trigger((s1, 50, "Attempt to connect to %s failed" % r1.name),
                (r1, 50, "Unable to initialize connection with"))
        sy.stop()
        trigger((s1, 20, "Finished shutting down"),
                (r1, 20, "Finished shutting down"))
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)

def testExpiredAuthorityTLS():
    """
    Test to see if we can start a sender/receiver pair, that they
    connect, and that they shut down properly.
    """
    _testFailedConnection("ca-expired-cert.pem", "signed-expired-ca-key.pem",
                          "signed-expired-ca-cert.pem")

def testExpiredCertificateTLS():
    """
    Test to see if we can start a sender/receiver pair, that they
    connect, and that they shut down properly.
    """
    _testFailedConnection("ca_cert_key8.pem", "expired-key.pem",
                          "expired-cert.pem")

def testMismatchedCertsTLS():
    hostname = "127.0.0.1"
    if not tls_supported():
        return None
    s1 = RwsenderCert(
        name=None, ca_cert=os.path.join(srcdir, "tests", "ca_cert_key8.pem"),
        key=None,
        cert=os.path.join(srcdir, "tests", "cert-key5-ca_cert_key8.p12"))
    r1 = RwreceiverCert(
        name=None, ca_cert=os.path.join(srcdir, "tests", "other-ca-cert.pem"),
        key=os.path.join(srcdir, "tests", "other-key.pem"),
        cert=os.path.join(srcdir, "tests", "other-cert.pem"))
    sy = SystemCert()
    try:
        sy.connect(r1, s1, tls=True, hostname=hostname)
        sy.start()
        check_started([r1], [s1], tls=True)
        trigger((r1, 50, "Attempt to connect to %s failed" % s1.name),
                (s1, 50, "Unable to initialize connection with"))
        sy.stop()
        trigger((s1, 20, "Finished shutting down"),
                (r1, 20, "Finished shutting down"))
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)

def testOtherCertsTLS():
    hostname = "127.0.0.1"
    if not tls_supported():
        return None
    s1 = RwsenderCert(
        name=None, ca_cert=os.path.join(srcdir, "tests", "other-ca-cert.pem"),
        key=os.path.join(srcdir, "tests", "other-key.pem"),
        cert=os.path.join(srcdir, "tests", "other-cert.pem"))
    r1 = RwreceiverCert(
        name=None, ca_cert=os.path.join(srcdir, "tests", "other-ca-cert.pem"),
        key=os.path.join(srcdir, "tests", "other-key.pem"),
        cert=os.path.join(srcdir, "tests", "other-cert.pem"))
    sy = SystemCert()
    try:
        sy.connect(r1, s1, tls=True, hostname=hostname)
        sy.start()
        check_started([r1], [s1], tls=True)
        check_connected([r1], [s1])
        sy.stop()
        trigger((s1, 20, "Finished shutting down"),
                (r1, 20, "Finished shutting down"))
        trigger((s1, 25, "Stopped logging"),
                (r1, 25, "Stopped logging"))
    except:
        traceback.print_exc()
        sy.stop()
        raise
    finally:
        sy.end(noremove=NO_REMOVE)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option("--verbose", action="store_true", dest="verbose",
                      default=False)
    parser.add_option("--overwrite-dirs", action="store_true",
                      dest="overwrite", default=False)
    parser.add_option("--save-output", action="store_true", dest="save_output",
                      default=False)
    parser.add_option("--log-level", action="store", type="string",
                      dest="log_level", default="info")
    parser.add_option("--log-output-to", action="store", type="string",
                      dest="log_output", default=None)
    parser.add_option("--file-list-file", action="store", type="string",
                      dest="file_list_file", default=None)
    parser.add_option("--print-test-names", action="store_true",
                      dest="print_test_names", default=False)
    parser.add_option("--timeout-factor", action="store", type="float",
                      dest="timeout_factor", default = 1.0)
    (options, args) = parser.parse_args()

    if options.print_test_names:
        print_test_names()
        sys.exit()

    if not options.file_list_file:
        sys.exit("The --file-list-file switch is required when running tests")

    FILE_LIST_FILE = options.file_list_file
    OVERWRITE = options.overwrite
    LOG_LEVEL = options.log_level
    NO_REMOVE = options.save_output

    (fd, path) = tempfile.mkstemp(".log", "sendrcv-", None)
    LOG_OUTPUT.append(os.fdopen(fd, "a"))
    if options.verbose:
        LOG_OUTPUT.append(sys.stdout)
    if options.log_output:
        LOG_OUTPUT.append(open(options.log_output, "a"))

    TIMEOUT_FACTOR = options.timeout_factor

    if not args:
        args = ALL_TESTS

    setup()
    retval = 1

    try:
        for x in args:
            locals()[x]()
    except SystemExit:
        raise
    finally:
        teardown()
