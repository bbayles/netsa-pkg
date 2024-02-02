#######################################################################
## Copyright (C) 2008-2023 by Carnegie Mellon University.
##
## @OPENSOURCE_LICENSE_START@
##
## SiLK 3.22.0
##
## Copyright 2023 Carnegie Mellon University.
##
## NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
## INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
## UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
## AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
## PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
## THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
## ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
## INFRINGEMENT.
##
## Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
## contact permission@sei.cmu.edu for full terms.
##
## [DISTRIBUTION STATEMENT A] This material has been approved for public
## release and unlimited distribution.  Please see Copyright notice for
## non-US Government use and distribution.
##
## GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
##
## Contract No.: FA8702-15-D-0002
## Contractor Name: Carnegie Mellon University
## Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
##
## The Government's rights to use, modify, reproduce, release, perform,
## display, or disclose this software are restricted by paragraph (b)(2) of
## the Rights in Noncommercial Computer Software and Noncommercial Computer
## Software Documentation clause contained in the above identified
## contract. No restrictions apply after the expiration date shown
## above. Any reproduction of the software or portions thereof marked with
## this legend must also reproduce the markings.
##
## Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
## Trademark Office by Carnegie Mellon University.
##
## This Software includes and/or makes use of Third-Party Software each
## subject to its own license.
##
## DM23-0973
##
## @OPENSOURCE_LICENSE_END@
##
#######################################################################

#######################################################################
# $SiLK: silk-python-info.py 05a9d0a040e2 2023-05-16 18:29:48Z mthomas $
#######################################################################

import sys
import os
import re

# Use library/sysconfig for >= 3.10; distutils/sysconfig for older
if sys.hexversion >= 0x030a0000:
    use_lib_sysconfig = True
    import sysconfig
else:
    use_lib_sysconfig = False
    from distutils import sysconfig


if len(sys.argv) > 1 and sys.argv[1] in ("--check-version", "--print-version"):
    # See if we are python version >= 2.4 and < 4.0
    version_ok = (0x020400f0 <= sys.hexversion < 0x04000000)
    if sys.argv[1] == "--print-version":
        sys.stdout.write("%d.%d.%d\n" % sys.version_info[0:3])
    if version_ok:
        sys.exit(0)
    else:
        sys.exit(1)

if len(sys.argv) == 1 or sys.argv[1] != "--filename":
    sys.exit("Usage: %s {--check-version | --print-version | --filename FILENAME}" %
             sys.argv[0])

# Result file
outfile = sys.argv[2]

# How configure passes settings to this script
python_prefix = os.getenv('PYTHONPREFIX')
python_site = os.getenv('PYTHONSITEDIR')

# The following variables are written to the output file at the end of
# this program, where each variable 'foo' is named 'PYTHON_FOO' except
# for 'error_string' which becomes 'PYTHON_ERROR'.
#
version = ""
libdir = ""
libname = ""
site_pkg = ""
default_site_pkg = ""
so_extension = ""
cppflags = ""
ldflags = ""
ldflags_embedded = ""
ldflags_pthread = ""
ldflags_embedded_pthread = ""
error_string = ""


try:
    version = "%d.%d.%d" % sys.version_info[0:3]

    # Stash the config vars
    config_vars = sysconfig.get_config_vars()

    # remove any space between a -L and a directory (for libtool)
    for k,v in config_vars.items():
        try:
            config_vars[k] = re.sub(r'-L +/', r'-L/', v)
        except:
            config_vars[k] = v

    # Get the Platform-specific Site-specific module directory.  Even
    # if the user provides the PYTYHONSITEDIR, this location is used
    # to determine whether to remind user to set their PYTHONPATH
    if use_lib_sysconfig:
        default_site_pkg = sysconfig.get_path('platlib')
    else:
        default_site_pkg = sysconfig.get_python_lib(True, False)

    # Where should we install packages?
    if python_site:
        # We were given a location
        site_pkg = python_site
    elif not python_prefix:
        # We were not given a location or a prefix; use default
        site_pkg = default_site_pkg
    elif use_lib_sysconfig:
        # Append to the given prefix the value of default_site_pkg
        # relative to the base directory.
        basedir = os.path.commonpath(
            [p for p in sysconfig.get_paths().values()])
        site_pkg = os.path.join(python_prefix,
                                os.path.relpath(basedir, default_site_pkg))
    elif default_site_pkg != sysconfig.get_python_lib(True, False, "BOGUS"):
        # prefix argument to get_python_lib() works
        site_pkg = sysconfig.get_python_lib(True, False, python_prefix)
    else:
        # prefix argument does not work (Mac OS-X, some versions)
        error_string = "--with-python-prefix is broken on this version of Python.  Please use --with-python-site-dir instead."

    # Python include path; used to create cppflags
    include_dir = ""
    if use_lib_sysconfig:
        include_dir = sysconfig.get_path('include')
    else:
        include_dir = sysconfig.get_python_inc()
    # The include_dir set by the above is sometimes wrong for Python
    # installed in /opt/rh/rh-python*/, so fix if necessary
    if not os.path.exists(os.path.join(include_dir, "Python.h")):
        incl = config_vars.get('INCLUDEPY', "/")
        if os.path.exists(os.path.join(incl, "Python.h")):
            include_dir = incl
        else:
            incl = config_vars.get('CONFINCLUDEPY', "/")
            if os.path.exists(os.path.join(incl, "Python.h")):
                include_dir = incl
            # The other potential variable to check is INCLDIRSTOMAKE
            # which returns a list of directories.

    # Python shared library extension
    so_extension = config_vars.get('SHLIB_SUFFIX')
    if not so_extension:
        so_extension = config_vars.get('SO', ".so")

    # Python library
    library = config_vars['LIBRARY']
    if not library:
        library = config_vars['LDLIBRARY']

    # Figure out the shortname of the library
    if library:
        library_nosuffix = (os.path.splitext(library))[0]
        libname = re.sub(r"^lib", "", library_nosuffix)

    # Python library location
    if library_nosuffix:
        # Cygwin puts library into BINDIR
        for var in ['LIBDIR', 'BINDIR']:
            path = config_vars[var]
            if path and os.path.isdir(path):
                if [item for item in os.listdir(path)
                    if re.match(library_nosuffix, item)
                       and not re.search(r"\.a$", item)]:
                    libdir = path
                    break

    # Needed for linking embedded python
    enable_shared = config_vars['Py_ENABLE_SHARED']
    linkforshared = config_vars['LINKFORSHARED']
    #localmodlibs = config_vars['LOCALMODLIBS']
    #basemodlibs = config_vars['BASEMODLIBS']
    more_ldflags = config_vars['LDFLAGS']
    python_framework = config_vars['PYTHONFRAMEWORK']
    libpl = config_vars['LIBPL']
    libs = config_vars['LIBS']
    syslibs = config_vars['SYSLIBS']

    # Remove hardening spec from LDFLAGS on Fedora
    more_ldflags = re.sub(r'-specs=/usr/lib/rpm/redhat/redhat-hardened-ld', '',
                          more_ldflags)

    ldflags_embedded = ' '.join([more_ldflags, #linkforshared,
                                 #basemodlibs, localmodlibs,
                                 libs, syslibs]).strip(' ')
    if not enable_shared and libpl:
        ldflags_embedded = '-L' + libpl + ' ' + ldflags_embedded
    if not python_framework and linkforshared:
        ldflags_embedded = ldflags_embedded + ' ' + linkforshared

    ### Build the output flags
    if include_dir:
        cppflags = "-I" + include_dir

    #if more_ldflags:
    #    ldflags = more_ldflags

    if libdir:
        ldflags += " -L" + libdir

    if libname:
        ldflags += " -l" + libname

    ldflags_embedded = ldflags + " " + ldflags_embedded

    # Hack for pthread support
    split_ldflags = ldflags.split()
    split_ldflags_embedded = ldflags_embedded.split()
    thread_flags = ['-lpthread', '-pthread']

    in_ldflags = [x for x in (split_ldflags + config_vars['CC'].split())
                  if x in thread_flags]
    if in_ldflags:
        ldflags_pthread = thread_flags['-lpthread' not in in_ldflags]

    in_ldflags_embedded = [x for x in
                           (split_ldflags_embedded + config_vars['CC'].split())
                           if x in thread_flags]
    if in_ldflags_embedded:
        ldflags_embedded_pthread = thread_flags['-lpthread' not in
                                                in_ldflags_embedded]

    if ldflags_pthread:
        split_ldflags = [x for x in split_ldflags
                         if x not in thread_flags]
        ldflags = ' '.join(split_ldflags)

    if ldflags_embedded_pthread:
        split_ldflags_embedded = [x for x in split_ldflags_embedded
                                  if x not in thread_flags]
        ldflags_embedded = ' '.join(split_ldflags_embedded)

    if (ldflags_pthread and ldflags_embedded_pthread and
        (ldflags_pthread == '-lpthread' or
         ldflags_embedded_pthread == '-lpthread')):
        ldflags_pthread = '-lpthread'
        ldflags_embedded_pthread = '-lpthread'

except:
    error_string = sys.exc_info()[1]
    pass

if outfile == "-":
    out = sys.stdout
else:
    try:
        if sys.hexversion < 0x03000000:
            out = open(outfile, "w")
        else:
            out = open(outfile, "w", encoding="ascii")
    except OSError:
        sys.exit("error: Cannot create %s" % outfile)

out.write("PYTHON_VERSION='%s'\n" % version)
out.write("PYTHON_LIBDIR='%s'\n" % libdir)
out.write("PYTHON_LIBNAME='%s'\n" % libname)
out.write("PYTHON_SITE_PKG='%s'\n" % site_pkg)
out.write("PYTHON_DEFAULT_SITE_PKG='%s'\n" % default_site_pkg)
out.write("PYTHON_SO_EXTENSION='%s'\n" % so_extension)
out.write("PYTHON_CPPFLAGS='%s'\n" % cppflags)
out.write("PYTHON_LDFLAGS='%s'\n" % ldflags)
out.write("PYTHON_LDFLAGS_EMBEDDED='%s'\n" % ldflags_embedded)
out.write("PYTHON_LDFLAGS_PTHREAD='%s'\n" % ldflags_pthread)
out.write("PYTHON_LDFLAGS_EMBEDDED_PTHREAD='%s'\n" %
          ldflags_embedded_pthread)
out.write("PYTHON_ERROR='%s'\n" % error_string)
out.close()
