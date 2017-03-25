#######################################################################
## Copyright (C) 2008-2017 by Carnegie Mellon University.
##
## @OPENSOURCE_LICENSE_START@
## See license information in ../LICENSE.txt
## @OPENSOURCE_LICENSE_END@
##
#######################################################################

#######################################################################
# $SiLK: silk-python-info.py 275df62a2e41 2017-01-05 17:30:40Z mthomas $
#######################################################################

from distutils.sysconfig import *
from distutils.util import get_platform
import sys
import os
import re

# See if we are python version >= 2.4 and < 4.0
version_ok = (0x020400f0 <= sys.hexversion < 0x04000000)

if len(sys.argv) > 1 and sys.argv[1] == "--check-version":
    if version_ok:
        sys.exit(0)
    else:
        sys.exit(1)

if len(sys.argv) > 1 and sys.argv[1] == "--print-version":
    sys.stdout.write("%d.%d.%d\n" % sys.version_info[0:3]);
    if version_ok:
        sys.exit(0)
    else:
        sys.exit(1)

if len(sys.argv) == 1 or sys.argv[1] != "--filename":
    sys.exit("Usage: %s {--check-version | --print-version | --filename FILENAME}" %
             sys.argv[0])

outfile = sys.argv[2]
python_prefix = os.getenv('PYTHONPREFIX')
python_site = os.getenv('PYTHONSITEDIR')
python_default_site = ""
version = ""
package_dest = ""
error_string = ""
include_dir = ""
ldflags = ""
cppflags = ""
libdir = ""
libname = ""
ldflags_embedded = ""
pthread_option = ""
pthread_embedded_option = ""
so_extension = ""


try:
    version = "%d.%d.%d" % sys.version_info[0:3]

    # Stash the config vars
    config_vars = get_config_vars()

    # remove any space between a -L and a directory (for libtool)
    for k,v in config_vars.items():
        try:
            config_vars[k] = re.sub(r'-L +/', r'-L/', v)
        except:
            config_vars[k] = v

    # Where should we install packages?
    python_default_site = get_python_lib(1,0)
    if python_site:
        package_dest = python_site
    else:
        if not python_prefix:
            package_dest = python_default_site
        elif python_default_site != get_python_lib(1,0,"BOGUS"):
            # prefix argument works
            package_dest = get_python_lib(1,0,python_prefix)
        else:
            # prefix argument does not work (Mac OS-X, some versions)
            error_string = "--with-python-prefix is broken on this version of Python.  Please use --with-python-site-dir instead."

    # Python include path
    include_dir = get_python_inc()

    # Python shared library extension
    so_extension = config_vars['SO']

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
        for var in ['LIBDIR', 'LIBPL', 'BINDIR']:
            path = config_vars[var]
            if path and os.path.isdir(path):
                if [item for item in os.listdir(path)
                    if re.match(library_nosuffix, item)
                       and not re.search(r"\.a$", item)]:
                    libdir = path
                    break

    # Needed for linking embedded python
    linkforshared = config_vars['LINKFORSHARED']
    localmodlibs = config_vars['LOCALMODLIBS']
    basemodlibs = config_vars['BASEMODLIBS']
    more_ldflags = config_vars['LDFLAGS']
    libs = config_vars['LIBS']
    syslibs = config_vars['SYSLIBS']
    ldflags_embedded = ' '.join([more_ldflags, linkforshared,
                                 basemodlibs, localmodlibs, libs,
                                 syslibs]).strip(' ')

    # Hack for the mac
    # Changes "-u _PyMac_Error Python.framework/Versions/2.4/Python" to
    # "-u _PyMac_Error -framework Python"
    ldflags_embedded = re.sub(r'(\A| )Python\.framework/[^ ]*',
                              ' -framework Python', ldflags_embedded)

    ### Build the output flags
    if include_dir:
        cppflags = "-I " + include_dir

    if more_ldflags:
        ldflags = more_ldflags

    if libdir:
        ldflags += " -L" + libdir

    if libname:
        ldflags += " -l" + libname

    ldflags_embedded = ldflags_embedded + " " + ldflags

    # Hack for pthread support
    split_ldflags = ldflags.split()
    split_ldflags_embedded = ldflags_embedded.split()
    thread_flags = ['-lpthread', '-pthread']

    in_ldflags = [x for x in (split_ldflags + config_vars['CC'].split())
                  if x in thread_flags]
    if in_ldflags:
        pthread_option = thread_flags['-lpthread' not in in_ldflags]

    in_ldflags_embedded = [x for x in
                           (split_ldflags_embedded + config_vars['CC'].split())
                           if x in thread_flags]
    if in_ldflags_embedded:
        pthread_embedded_option = thread_flags['-lpthread' not in
                                               in_ldflags_embedded]

    if pthread_option:
        split_ldflags = [x for x in split_ldflags
                         if x not in thread_flags]
        ldflags = ' '.join(split_ldflags)


    if pthread_embedded_option:
        split_ldflags_embedded = [x for x in split_ldflags_embedded
                                  if x not in thread_flags]
        ldflags_embedded = ' '.join(split_ldflags_embedded)

    if (pthread_option and pthread_embedded_option and
        (pthread_option == '-lpthread' or
         pthread_embedded_option == '-lpthread')):
        pthread_option = '-lpthread'
        pthread_embedded_option = '-lpthread'

except:
    error_string = sys.exc_info()[1]
    pass

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
out.write("PYTHON_SITE_PKG='%s'\n" % package_dest)
out.write("PYTHON_DEFAULT_SITE_PKG='%s'\n" % python_default_site)
out.write("PYTHON_SO_EXTENSION='%s'\n" % so_extension)
out.write("PYTHON_CPPFLAGS='%s'\n" % cppflags)
out.write("PYTHON_LDFLAGS='%s'\n" % ldflags)
out.write("PYTHON_LDFLAGS_EMBEDDED='%s'\n" % ldflags_embedded)
out.write("PYTHON_LDFLAGS_PTHREAD='%s'\n" % pthread_option)
out.write("PYTHON_LDFLAGS_EMBEDDED_PTHREAD='%s'\n" %
         pthread_embedded_option)
out.write("PYTHON_ERROR='%s'\n" % error_string)
out.close()
