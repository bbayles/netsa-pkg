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
# $SiLK: gencerts.py b2b562f1ea39 2023-02-20 17:50:25Z mthomas $
#######################################################################

import sys
import os
import os.path
import re
import subprocess

top_builddir = os.environ.get('top_builddir')
if top_builddir:
    sys.path.insert(0, os.path.join(top_builddir, "tests"))
from config_vars import config_vars

certtool = os.environ.get('CERTTOOL')
if not certtool:
    certtool = 'certtool'

PASSWORD = "x"

key_bits = 1024

tls_template = """
organization = "test"
unit = "test"
state = "test"
country = US
cn = "test"
serial = 001
"""

tls_ca_template = tls_template + """
expiration_days = 18301
ca
signing_key
cert_signing_key
"""

tls_prog_template = tls_template + """
expiration_days = 18300
signing_key
encryption_key
"""

tls_p12_template = """
pkcs12_key_name = "test"
password = "%s"
""" % PASSWORD

r = re.compile(r'key[0-9]+\.pem$')
srcdir = os.environ.get("srcdir")
if srcdir is None:
    srcdir = os.path.join(config_vars["abs_srcdir"],
                          "..", "src", "sendrcv")
keyloc = os.path.join(srcdir, "tests")
potentials = [os.path.join(keyloc, x) for x in os.listdir(keyloc)
              if r.match(x)]
potentials_used = []

r = re.compile(r'ca_cert_(key[0-9]+\.pem)$')
ca_certs = []
ca_certs_used = []
for f in os.listdir(keyloc):
    match = r.match(f)
    if match:
        key = os.path.join(keyloc, match.group(1))
        try:
            potentials.remove(key)
        except ValueError:
            pass
        ca_certs.append((key, os.path.join(keyloc, f)))

r = re.compile(r'cert-([^-]+)-(.+)\.p12$')
p12_map = {}
for f in os.listdir(keyloc):
    match = r.match(f)
    if match:
        p12 = os.path.join(keyloc, f)
        ca = match.group(2)
        if ca in p12_map:
            p12_map[ca].append(p12)
        else:
            p12_map[ca] = [p12]
p12s_used = []


def check_call(*popenargs, **kwargs):
    sys.stderr.write('Calling "%s"\n' % ' '.join(*popenargs))
    sys.stderr.flush()
    if subprocess.call(*popenargs, **kwargs):
        raise RuntimeError('Failed to execute "%s"' % ' '.join(*popenargs))


def check_certtool():
    sys.stderr.write('Calling "%s --version"\n' % certtool)
    sys.stderr.flush()
    proc = subprocess.Popen([certtool, '--version'], close_fds=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = proc.stdout.read()
    if not re.search(br"(?i)\b(lib)?gnutls\b", output):
        raise RuntimeError(
            "Found %s program but it not associated with GnuTLS" % certtool)


def create_certs(tmpdir):
    ca_cert_pair = generate_ca_cert(tmpdir, "ca_cert.pem")
    newname = "ca_cert_" + os.path.basename(ca_cert_pair[0])
    sys.stderr.write('mv "%s" "%s"\n' % (ca_cert_pair[1], newname))
    sys.stderr.flush()
    os.rename(ca_cert_pair[1], newname)
    ca_cert_pair = (ca_cert_pair[0], newname)
    key = get_key()
    while key:
        key_base = os.path.splitext(os.path.basename(key))[0]
        ca_base = os.path.splitext(os.path.basename(ca_cert_pair[1]))[0]
        newname = "cert-" + key_base + "-" + ca_base + ".p12"
        generate_signed_cert(tmpdir, ca_cert_pair, key, newname)
        key = get_key()

def reset_used_keys():
    global potentials
    global potentials_used
    potentials.extend(potentials_used)
    used = []

def get_key():
    global potentials
    global potentials_used
    if potentials:
        key = potentials.pop()
        potentials_used.append(key)
        return key
    return None

def generate_key(filename):
    name = get_key()
    if not name:
        name = filename
        check_certtool()
        check_call(
            [certtool, '--generate-privkey', '--outfile', filename,
             '--bits', str(key_bits)])
    return name

def get_ca_cert():
    global ca_certs
    global ca_certs_used
    if ca_certs:
        cert = ca_certs.pop()
        ca_certs_used.append(cert)
        return cert

def reset_ca_certs():
    global ca_certs
    global ca_certs_used
    ca_certs.extend(ca_certs_used)
    ca_certs_used = []


def create_self_signed_ca_cert(tmpdir, key, filename):
    template = os.path.join(tmpdir, "ca_template")
    template_file = open(template, "w")
    template_file.write(tls_ca_template)
    template_file.close()
    check_certtool()
    check_call(
        [certtool, '--generate-self-signed', '--template',
         template, '--load-privkey', key, '--outfile', filename])

def generate_ca_cert(tmpdir, filename):
    ca_cert = get_ca_cert()
    if not ca_cert:
        key = generate_key(os.path.join(tmpdir, "ca_key.pem"))
        ca_cert = (key, filename)
        create_self_signed_ca_cert(tmpdir, key, filename)
    return ca_cert


def create_signed_cert(tmpdir, ca_cert_pair, key, filename):
    (ca_key, ca_cert) = ca_cert_pair
    template = os.path.join(tmpdir, "prog_template")
    template_file = open(template, "w")
    template_file.write(tls_prog_template)
    template_file.close()
    template12 = os.path.join(tmpdir, "template12")
    template12_file = open(template12, "w")
    template12_file.write(tls_p12_template)
    template12_file.close()
    check_certtool()
    check_call(
        [certtool, '--generate-request', '--load-privkey', key,
         '--outfile', os.path.join(tmpdir, 'request.pem'),
         '--template', template])
    check_call(
        [certtool, '--generate-certificate',
         '--load-request', os.path.join(tmpdir, 'request.pem'),
         '--outfile', os.path.join(tmpdir, 'cert.pem'),
         '--template', template,
         '--load-ca-certificate', ca_cert,
         '--load-ca-privkey', ca_key])
    check_call(
        [certtool,
         '--load-certificate', os.path.join(tmpdir, 'cert.pem'),
         '--load-privkey', key,
         '--to-p12', '--outder', '--template', template12,
         '--outfile', filename])

def generate_signed_cert(tmpdir, ca_cert_pair, key, filename):
    global p12_map
    global p12s_used
    (ca_key, ca_cert) = ca_cert_pair
    basecert = os.path.splitext(os.path.basename(ca_cert))[0]
    if basecert in p12_map:
        plist = p12_map[basecert]
        p12 = plist.pop()
        p12s_used.append((basecert, p12))
        return p12
    if not os.path.exists(key):
        key = generate_key(key)
    create_signed_cert(tmpdir, ca_cert_pair, key, filename)
    return filename

def reset_used_certs():
    global p12_map
    global p12s_used
    for key, value in p12s_used:
        p12_map[key].append(value)
    p12s_used = []

def reset_all_certs_and_keys():
    reset_used_keys()
    reset_ca_certs()
    reset_used_certs()

######  generating an expired certificate and key that uses the standard CA
# $ cat expire.tmpl
# organization = "SiLK rwsender/rwreceiver"
# activation_date = "2018-11-14 16:00:00"
# expiration_date = "2018-11-14 16:00:16"
# encryption_key
# signing_key
# $ gnutls-certtool --generate-privkey > tests/expired-key.pem
# $ gnutls-certtool --generate-certificate         \
#     --load-ca-privkey tests/key8.pem             \
#     --load-ca-certificate tests/ca_cert_key8.pem \
#     --load-privkey tests/expired-key.pem         \
#     --template expire.tmpl                       \
#     --outfile tests/expired-cert.pem

######  generating a different CA and key+cert that is signed by that CA
# $ cat ca.tmpl
# cn = 'SiLK Test CA'
# expiration_days = 18300
# ca
# cert_signing_key
# $ gnutls-certtool --generate-privkey > tests/other-ca-key.pem
# $ gnutls-certtool --generate-self-signed  \
#     --load-privkey tests/other-ca-key.pem \
#     --template ca.tmpl                    \
#     --outfile tests/other-ca-cert.pem
# $ cat other.tmpl
# organization = "SiLK rwsender/rwreceiver"
# expiration_days = 18299
# encryption_key
# signing_key
# $ gnutls-certtool --generate-privkey > tests/other-key.pem
# $ gnutls-certtool --generate-certificate          \
#     --load-ca-privkey tests/other-ca-key.pem      \
#     --load-ca-certificate tests/other-ca-cert.pem \
#     --load-privkey tests/other-key.pem            \
#     --template other.tmpl                         \
#     --outfile tests/other-cert.pem
# $ gnutls-certtool --to-p12                       \
#     --load-ca-certificate tests/other-ca-key.pem \
#     --load-privkey tests/other-key.pem           \
#     --load-certificate tests/other-cert.pem      \
#     --outder --outfile tests/other.p12           \
#     --p12-name=other --empty-password

######  generating an expired CA and "valid" key+cert that is signed by it
# $ cat ca-expire.tmpl
# cn = 'SiLK Test CA'
# activation_date = "2018-11-12 13:14:15"
# expiration_date = "2018-11-12 13:14:16"
# ca
# cert_signing_key
# $ gnutls-certtool --generate-privkey > tests/ca-expired-key.pem
# $ gnutls-certtool --generate-self-signed    \
#     --load-privkey tests/ca-expired-key.pem \
#     --template ca-expire.tmpl               \
#     --outfile tests/ca-expired-cert.pem
# $ cat other.tmpl
# organization = "SiLK rwsender/rwreceiver"
# expiration_days = 18299
# encryption_key
# signing_key
# $ gnutls-certtool --generate-privkey > tests/key-signed-expired-ca.pem
# $ gnutls-certtool --generate-certificate            \
#     --load-ca-privkey tests/ca-expired-key.pem      \
#     --load-ca-certificate tests/ca-expired-cert.pem \
#     --load-privkey tests/key-signed-expired-ca.pem  \
#     --template other.tmpl                           \
#     --outfile tests/cert-signed-expired-ca.pem
# $ gnutls-certtool --to-p12                       \
#     --load-ca-certificate tests/signed-expired-ca-ca-key.pem \
#     --load-privkey tests/signed-expired-ca-key.pem           \
#     --load-certificate tests/signed-expired-ca-cert.pem      \
#     --outder --outfile tests/signed-expired-ca.p12           \
#     --p12-name=other --empty-password


if __name__ == '__main__':
    if not potentials:
        for i in range(1,9):
            generate_key("key%s.pem" % i)
    else:
        create_certs("/tmp")
