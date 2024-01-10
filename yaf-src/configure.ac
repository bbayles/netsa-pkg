dnl Copyright 2005-2023 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.in
dnl autotools build system for YAF applications
dnl ------------------------------------------------------------------------
dnl Authors: Brian Trammell
dnl ------------------------------------------------------------------------
dnl @DISTRIBUTION_STATEMENT_BEGIN@
dnl YAF 2.15.0
dnl
dnl Copyright 2023 Carnegie Mellon University.
dnl
dnl NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
dnl INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
dnl UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
dnl AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
dnl PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
dnl THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
dnl ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
dnl INFRINGEMENT.
dnl
dnl Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
dnl contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for public
dnl release and unlimited distribution.  Please see Copyright notice for
dnl non-US Government use and distribution.
dnl
dnl GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
dnl Contract No.: FA8702-15-D-0002
dnl Contractor Name: Carnegie Mellon University
dnl Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
dnl
dnl The Government's rights to use, modify, reproduce, release, perform,
dnl display, or disclose this software are restricted by paragraph (b)(2) of
dnl the Rights in Noncommercial Computer Software and Noncommercial Computer
dnl Software Documentation clause contained in the above identified
dnl contract. No restrictions apply after the expiration date shown
dnl above. Any reproduction of the software or portions thereof marked with
dnl this legend must also reproduce the markings.
dnl
dnl This Software includes and/or makes use of Third-Party Software each
dnl subject to its own license.
dnl
dnl DM23-2313
dnl @DISTRIBUTION_STATEMENT_END@
dnl ------------------------------------------------------------------------

AC_PREREQ([2.64])
AC_INIT([yaf],[2.15.0],[netsa-help@cert.org],[yaf],[https://tools.netsa.certo.org/yaf2/])
AC_COPYRIGHT([Copyright (C) 2006-2023 by Carnegie Mellon University
GNU General Public License (GPL) Rights pursuant to Version 2, June 1991])
AC_CONFIG_SRCDIR([src/yaf.c])
AC_CONFIG_AUX_DIR([autoconf])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE([1.6.3 foreign check-news subdir-objects])
LIBCOMPAT="4:0:0"
AC_CONFIG_HEADERS([include/yaf/config.h])
AC_CONFIG_HEADERS([airframe/include/airframe/config.h])
AH_TOP([/*
 *  Copyright 2006-2023 Carnegie Mellon University
 *  See license information in LICENSE.txt.
 */
/*
 *  autoheader generated header file
 *  ------------------------------------------------------------------------
 *  @DISTRIBUTION_STATEMENT_BEGIN@
 *  YAF 2.15.0
 *
 *  Copyright 2023 Carnegie Mellon University.
 *
 *  NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 *  INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 *  UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 *  AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 *  PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 *  THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 *  ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 *  INFRINGEMENT.
 *
 *  Licensed under a GNU GPL 2.0-style license, please see LICENSE.txt or
 *  contact permission@sei.cmu.edu for full terms.
 *
 *  [DISTRIBUTION STATEMENT A] This material has been approved for public
 *  release and unlimited distribution.  Please see Copyright notice for
 *  non-US Government use and distribution.
 *
 *  GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
 *  Contract No.: FA8702-15-D-0002
 *  Contractor Name: Carnegie Mellon University
 *  Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
 *
 *  The Government's rights to use, modify, reproduce, release, perform,
 *  display, or disclose this software are restricted by paragraph (b)(2) of
 *  the Rights in Noncommercial Computer Software and Noncommercial Computer
 *  Software Documentation clause contained in the above identified
 *  contract. No restrictions apply after the expiration date shown
 *  above. Any reproduction of the software or portions thereof marked with
 *  this legend must also reproduce the markings.
 *
 *  This Software includes and/or makes use of Third-Party Software each
 *  subject to its own license.
 *
 *  DM23-2313
 *  @DISTRIBUTION_STATEMENT_END@
 */])

AC_SUBST([YAF_REQ_AIRFRAME_VER], [2.0.0])

RPM_CONFIG_FLAGS=""


dnl ----------------------------------------------------------------------
dnl Check for (or install) libltdl #AC_LIBTOOL_DLOPEN
dnl ----------------------------------------------------------------------

LT_CONFIG_LTDL_DIR([libltdl])
LT_INIT([dlopen disable-static])
LTDL_INIT()

if test yes != "$with_included_ltdl"; then
   AC_MSG_NOTICE([using system libltdl])
else
   AC_MSG_NOTICE([building convenience libltdl])
fi
  

dnl -------------------------------------
dnl set version of plugins
dnl -------------------------------------
version_info="1:1:0"
AC_SUBST([version_info])

AC_LANG([C])
AC_PROG_CC
AC_PROG_CC_C_O
AX_ENABLE_WARNINGS

AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

dnl -------------------------------------
dnl add a default set of include directories
dnl -------------------------------------
if test "x${srcdir}" = x.
then
    YAF_CPPFLAGS='-I$(top_srcdir)/include -I$(top_srcdir)/airframe/include'
else
    YAF_CPPFLAGS='-I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_builddir)/airframe/include -I$(top_srcdir)/airframe/include'
fi
AC_SUBST([YAF_CPPFLAGS])

AC_CHECK_HEADERS([errno.h fcntl.h glob.h signal.h sys/errno.h grp.h malloc.h])
AC_CHECK_HEADERS([netdb.h netinet/in.h pwd.h stdarg.h stddef.h sys/socket.h syslog.h])
AC_CHECK_HEADERS([inttypes.h limits.h ctype.h stdlib.h search.h math.h])

AC_SEARCH_LIBS([nanosleep], [rt])
AC_SEARCH_LIBS([inet_ntoa], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([log], [m])

AC_CHECK_FUNCS([atexit clock_gettime gethostbyname gethostname gettimeofday memchr memset pow sqrt strchr strdup strerror strstr strtoul strtoull], [], [
  AC_MSG_NOTICE([Not all required C functions were found. Code may fail to compile.])])
dnl Additional functions from airframe
AC_CHECK_FUNCS([localtime_r select socket strrchr], [], [AC_MSG_NOTICE(
    [Not all required C functions were found. Code may fail to compile.])])


dnl ----------------------------------------------------------------------
dnl Check for getaddrinfo
dnl ----------------------------------------------------------------------
AC_CHECK_FUNCS([getaddrinfo])


dnl ----------------------------------------------------------------------
dnl figure out the right format string for printing size_t
dnl ----------------------------------------------------------------------

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

YF_SIZE_T_FORMAT

AC_STRUCT_DIRENT_D_TYPE

dnl ----------------------------------------------------------------------
dnl Set up doxygen
dnl ----------------------------------------------------------------------

DX_HTML_FEATURE([ON])
DX_CHM_FEATURE([OFF])
DX_CHI_FEATURE([OFF])
DX_MAN_FEATURE([OFF])
DX_RTF_FEATURE([OFF])
DX_XML_FEATURE([OFF])
DX_PDF_FEATURE([OFF])
DX_PS_FEATURE([OFF])
DX_INIT_DOXYGEN([yaf], [Doxyfile], [doc])

dnl ----------------------------------------------------------------------
dnl Set up pod2man
dnl ----------------------------------------------------------------------

AC_CHECK_PROGS([POD2MAN], [pod2man], [:])
AC_ARG_VAR([POD2MAN], [Perl POD markup language to man page tool])
AM_CONDITIONAL([HAVE_POD2MAN], [test "x${POD2MAN}" != "x:"])

YAF_POD2MAN_ARGS="--center='Yet Another Flowmeter' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"
AIRFRAME_POD2MAN_ARGS="--center='airframe' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"

AC_SUBST([YAF_POD2MAN_ARGS])
AC_SUBST([AIRFRAME_POD2MAN_ARGS])

dnl ----------------------------------------------------------------------
dnl Set up pod2html
dnl ----------------------------------------------------------------------
AC_ARG_VAR([POD2HTML], [Perl POD markup language to HTML tool])
AM_MISSING_PROG([POD2HTML], [pod2html])


dnl ----------------------------------------------------------------------
dnl Check for script to update the distribution statement
dnl ----------------------------------------------------------------------
update_markings="${srcdir}/maint/update-document-marking.pl"
AC_CHECK_FILE([${update_markings}], [
    AC_SUBST([UPDATE_MARKINGS], ${update_markings})
])
AM_CONDITIONAL([HAVE_UPDATE_MARKINGS], [test -n "${UPDATE_MARKINGS}"])


dnl ----------------------------------------------------------------------
dnl Check for Lua
dnl ----------------------------------------------------------------------
#AX_CHECK_LIBLUA
AC_CONFIG_SUBDIRS([lua])

# Symlink Lua headers to the top of YAF's src/include
AC_CONFIG_LINKS([
    src/lua.h:lua/src/lua.h
    src/luaconf.h:lua/src/luaconf.h
    src/lualib.h:lua/src/lualib.h
    src/lauxlib.h:lua/src/lauxlib.h
])

dnl ----------------------------------------------------------------------
dnl Check for aligned access required
dnl ----------------------------------------------------------------------

AX_CHECK_ALIGNED_ACCESS_REQUIRED


dnl ----------------------------------------------------------------------
dnl for some reason prefix does not get set here - so this is a nice hack
dnl ----------------------------------------------------------------------
if test "x$prefix" = "xNONE"; then
   prefix=/usr/local
fi

dnl ----------------------------------------------------------------------
dnl Modify PKG_CONFIG_PATH based on prefix
dnl ----------------------------------------------------------------------

if test "x$PKG_CONFIG_PATH" != "x"; then
    PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
else
    PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
    export PKG_CONFIG_PATH
fi

dnl ----------------------------------------------------------------------
dnl Check for prefix and set LTDL_LIBRARY_PATH
dnl ----------------------------------------------------------------------

if test "x$prefix" != "x"; then
   LTDL_LIBRARY_PATH="$LTDL_LIBRARY_PATH:$prefix/lib/yaf"
   export LTDL_LIBRARY_PATH
else
   LTDL_LIBRARY_PATH="$LTDL_LIBRARY_PATH:/usr/local/lib/yaf"
   export LTDL_LIBRARY_PATH
fi



dnl ----------------------------------------------------------------------
dnl Check for glib
dnl ----------------------------------------------------------------------

GLIB_PRESENT=NO
GLIB_LDADD=

yf_req_glib=2.18.0
AM_PATH_GLIB_2_0([${yf_req_glib}],[GLIB_PRESENT=YES])

AC_ARG_WITH([glib-static],
AS_HELP_STRING([--with-glib-static=prefix],[use static glib tree]),[
GLIB_STATIC_LIBGLIB2_A="${withval}/lib/libglib-2.0.a"
GLIB_STATIC_INCLUDE="${withval}/include/glib-2.0"
GLIB_STATIC_LIBINCLUDE="${withval}/lib/glib-2.0/include"
if test -f ${GLIB_STATIC_LIBGLIB2_A}; then
    if test -f "${GLIB_STATIC_INCLUDE}/glib.h"; then
        GLIB_LDADD=${GLIB_STATIC_LIBGLIB2_A}
        GLIB_CFLAGS="-I${GLIB_STATIC_INCLUDE} -I${GLIB_STATIC_LIBINCLUDE}"
        AC_SUBST([GLIB_LIBS])
        AC_SUBST([GLIB_CFLAGS])
        GLIB_PRESENT=YES
        AC_MSG_NOTICE([assuming static glib in ${withval} is good...])
    fi
fi
])

if test x"$GLIB_PRESENT" != "xYES"; then
  AC_MSG_ERROR([Cannot find a suitable glib2 (>= ${yf_req_glib}). Do you need to install glib2-devel or libglib2.0-dev?])
fi

AC_SUBST([YAF_REQ_GLIB_VER], [${yf_req_glib}])
AC_SUBST([GLIB_LDADD])
AC_SUBST([GLIB_CFLAGS])
AC_SUBST([GLIB_LIBS])
AC_SUBST([LIBLTDL])
AC_SUBST([LTDLINCL])

dnl ----------------------------------------------------------------------
dnl Check for popt
dnl ----------------------------------------------------------------------

use_popt=no
AC_ARG_WITH([popt], AS_HELP_STRING([--with-popt=path],[location of popt]),
[
    if test "x${with_popt}" != "xno"; then
        use_popt=yes
        if test "x${with_popt}" != "xyes"; then
            POPT_CLFAGS="-I${withval}/include"
            POPT_LDFLAGS="-L${withval}/lib -lpopt"
            CFLAGS="$CFLAGS ${POPT_CFLAGS}"
            CPPFLAGS="$CFLAGS ${POPT_CFLAGS}"
            LDFLAGS="$LDFLAGS ${POPT_LDFLAGS}"
        fi
    fi
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-popt=${with_popt}"

    if test "x$use_popt" = "xyes"; then
        AC_CHECK_LIB([popt],[poptParseArgvString],
        [
            AC_MSG_NOTICE([using libpopt found in ${with_popt} for options processing])
            AC_DEFINE([USE_POPT], [1], [Define to 1 to use libpopt])
        ],[
            AC_MSG_ERROR([libpopt was not found or is not usable])
        ])
    fi
])

if test "x${use_popt}" = xno ; then
    AC_MSG_NOTICE([using GLib for options processing])
    AC_DEFINE([USE_GOPTION], [1], [Define to 1 to enable use of GOption])
fi

dnl ----------------------------------------------------------------------
dnl Check for libfixbuf
dnl when changing the version number required, do both the subst, and
dnl package lines!
dnl ----------------------------------------------------------------------
yaf_req_fixbuf_ver=2.3.0
AC_SUBST([YAF_REQ_FIXBUF_VER], [${yaf_req_fixbuf_ver}])
PKG_CHECK_MODULES([libfixbuf],
    [libfixbuf >= ${yaf_req_fixbuf_ver} libfixbuf < 3.0.0],
    [],
    [AC_MSG_ERROR([Cannot find a suitable libfixbuf (>= ${yaf_req_fixbuf_ver}) (Try setting PKG_CONFIG_PATH): $libfixbuf_PKG_ERRORS])]
)
YF_PKGCONFIG_VERSION([libfixbuf])
fixbuf_install_loc=`$PKG_CONFIG --variable=prefix libfixbuf`
AC_MSG_NOTICE([libfixbuf version: $yfpkg_ver])
AC_MSG_NOTICE([Using libfixbuf installed in: $fixbuf_install_loc])
AC_DEFINE_UNQUOTED([FIXBUF_VERSION], ["$yfpkg_ver"], [fixbuf version])
fixbuf_version=$yfpkg_ver


dnl ----------------------------------------------------------------------
dnl Check for libpcap
dnl ----------------------------------------------------------------------
AC_ARG_WITH([libpcap],
    AS_HELP_STRING([--with-libpcap=PCAP_DIR],
        [find pcap.h in PCAP_DIR/include, libpcap in PCAP_DIR/lib]),
[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            if test -d ${withval}/lib; then
                CFLAGS="-I${withval}/include $CFLAGS"
                CPPFLAGS="$CPPFLAGS -I${withval}/include"
                if test "x$target_os" = "xcygwin"; then
                    LIBS="-L${withval}/lib -lwpcap $LIBS"
                else
                    LIBS="-L${withval}/lib -lpcap $LIBS"
                    if test "x$target_os" = "xlinux" -o \
                            "x$target_os" = "xlinux-gnu"; then
                        LIBS="-Wl,--rpath -Wl,${withval}/lib $LIBS"
                    fi
                fi
            else
                if test "x$target_os" = "xcygwin"; then
                    LIBS="-L${withval} -lwpcap $LIBS"
                else
                    LIBS="-L${withval} -lpcap $LIBS"
                    if test "x$target_os" = "xlinux" -o \
                            "x$target_os" = "xlinux-gnu"; then
                        LIBS="-Wl,--rpath -Wl,${withval} $LIBS"
                    fi
                fi
            fi
            pcap_from="${withval}"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-libpcap=${withval}"
        fi
        if test "x$target_os" = "xcygwin"; then
            AC_CHECK_LIB([wpcap],[pcap_open_offline],[],
                [AC_MSG_ERROR([cannot locate required WPCAP library])]
            )
        else
            AC_CHECK_LIB([pcap],[pcap_open_offline],[],
                [AC_MSG_ERROR([cannot locate required PCAP library. Do you need to install libpcap-devel or libpcap-dev?])]
            )
        fi
        AC_CHECK_HEADERS([pcap.h],[],
           [AC_MSG_ERROR([cannot locate required pcap.h header file])
        ])
    fi
],[
    if test "x$target_os" = "xcygwin"; then
        AC_CHECK_LIB([wpcap],[pcap_open_offline],[],
            [AC_MSG_ERROR([cannot locate required PCAP library, try the --with-libpcap option])]
        )
    else
        AC_CHECK_LIB([pcap],[pcap_open_offline],[],
            [AC_MSG_ERROR([cannot locate required PCAP library, try the --with-libpcap option])]
        )
    fi
    AC_CHECK_HEADERS([pcap.h], [],
        [AC_MSG_ERROR([cannot locate the required pcap.h header file])]
    )
])

dnl ----------------------------------------------------------------------
dnl check for disabling all payload handling
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([payload],
    AS_HELP_STRING([--disable-payload],
        [disable YAF from being built with payload handling capability]),
[
    if test "x$enableval" = "xno"; then
        nopayload=true
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-payload"
        AC_MSG_NOTICE([YAF payload processing is disabled])
    else
        AC_MSG_NOTICE([YAF payload processing is not disabled])
        nopayload=false
        AC_DEFINE([YAF_ENABLE_PAYLOAD], [1],
            [Define to 1 to enable yaf payload processing])
    fi
],[
    AC_DEFINE([YAF_ENABLE_PAYLOAD], [1],
        [Define to 1 to enable yaf payload processing])
    AC_MSG_NOTICE([Payload processing is enabled by default])
    nopayload=false
])

dnl ----------------------------------------------------------------------
dnl Check for libndpi
dnl ----------------------------------------------------------------------

AC_ARG_ENABLE([ndpi],
    AS_HELP_STRING([--enable-ndpi],
        [enable NDPI application labeling (requires the ndpi library) [default=no]]),
[
    if test "x${enableval}" != "xno"; then
        AC_MSG_NOTICE([Running tests for NDPI appliation labeling])
        # The nDPI API can change at arbitary times, and checking for
        # a maximum version is pointless
        PKG_CHECK_MODULES([libndpi], [libndpi >= 2.0],
        [],[
            AC_MSG_ERROR([Cannot find a suitable libndpi (>= 2.0) (Try setting PKG_CONFIG_PATH): $libndpi_PKG_ERRORS])
        ])

        # Save variables
        yf_save_LIBS="${LIBS}"
        yf_save_CFLAGS="${CFLAGS}"

        LIBS="${libndpi_LIBS} ${yf_save_LIBS}"
        CFLAGS="${yf_save_CFLAGS} ${libndpi_CFLAGS}"

        # Verify that the compiler can find all the libraries needed
        # for nDPI since nDPI does not always include the libs in the
        # libndpi.pc file.  We also do this to get accurate results
        # from the next AC_CHECK_FUNCS command.
        AC_CHECK_FUNC([ndpi_detection_process_packet], [], [
            AC_MSG_FAILURE([Unable to use -lndpi.  This is probably due to missing -L flags.  Add the required flags to LDFLAGS and try again.])
        ])

        # Check for a function added after 2.8.  Note that
        # initialization is misspelled in some releases
        AC_CHECK_FUNCS([ndpi_finalize_initialization ndpi_finalize_initalization])

        # Check whether the header is in a "/libndpi" subdirectory
        AC_CHECK_HEADER([ndpi_main.h],
        [
            ndpi=true
            AC_DEFINE([YAF_ENABLE_NDPI], [1], [Define to 1 to enable ndpi])
        ],[
            # Didn't find header, add /libndpi and check again
            libndpi_CFLAGS="${libndpi_CFLAGS}/libndpi"
            CFLAGS="${yf_save_CFLAGS} ${libndpi_CFLAGS}"
            AS_UNSET([ac_cv_header_ndpi_main_h])

            AC_CHECK_HEADER([ndpi_main.h],
            [
                ndpi=true
                AC_DEFINE([YAF_ENABLE_NDPI], [1], [Define to 1 to enable ndpi])
            ],[
                # No header found in either location
                AC_MSG_ERROR([Found LIBNDPI but not ndpi_main.h.  Maybe you should install ndpi-devel?])
            ], AC_INCLUDES_DEFAULT)
        ], AC_INCLUDES_DEFAULT)

        # Check for types that indicate API changes
        AC_CHECK_TYPES([ndpi_init_prefs, struct ndpi_id_struct], [], [], [
#include <ndpi_api.h>
        ])

        # Restore libraries
        LIBS="${yf_save_LIBS}"
        CFLAGS="${yf_save_CFLAGS}"
    fi
])

dnl ---------------------------------------------------------------------
dnl Check for pfring
dnl ---------------------------------------------------------------------
AC_ARG_WITH([pfring],
    AS_HELP_STRING([--with-pfring[=PFRING_DIR]],
        [include PF_RING support; find pfring.h in PFRING_DIR/include, libpfring in PFRING_DIR/lib]),
[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            if test -d ${withval}/lib; then
                LIBS="-L${withval}/lib -lpfring -lrt $LIBS"
                CFLAGS="$CFLAGS -I${withval}/include"
                CPPFLAGS="$CPPFLAGS -I${withval}/include"
            fi
        else
            LIBS="-lpfring -lrt $LIBS"
        fi

        AC_CHECK_LIB([pfring],[pfring_zc_numa_get_cpu_node],
        [
            AC_SUBST([YAF_HAS_PFRING], [1])
            AC_DEFINE([YAF_ENABLE_PFRING], [1],
                [Define to 1 to enable PFRING support])
            AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES],[1],
                [Define to 1 to enable YAF Separate Interface Support])
            AC_DEFINE([YAF_ENABLE_PFRINGZC], [1],
                [Define to 1 to enable PFRING ZC support])
            pfringzc=true
            pfring=true
        ],[
            AC_MSG_NOTICE([Cannot locate PFRING ZC library v. 6.2.0 or greater])
            pfringzc=false
            pfring=false
        ])

        AC_CHECK_HEADERS([pfring.h],
        [],[
            AC_MSG_ERROR([cannot open PFRING header file])
            pfring=false
        ])
        AC_CHECK_HEADERS([pfring_zc.h],
        [
            AC_DEFINE([YAF_ENABLE_PFRINGZC], [1],
                [Define to 1 to enable PFRING ZC support])
        ],[
            AC_MSG_NOTICE([cannot open PFRING ZC header file])
            pfringzc=false
        ])
    fi
])
AM_CONDITIONAL([HASPFRINGZC], [test x$pfringzc = xtrue])



dnl ----------------------------------------------------------------------
dnl Check for libdag
dnl ----------------------------------------------------------------------

AC_ARG_WITH([dag],
    AS_HELP_STRING([--with-dag[=DAG_DIR]],
        [include Endace DAG support; find dagapi.h in DAG_DIR/include, libdag in DAG_DIR/lib]),
[
    if test "x$withval" != "xno"; then
        AC_SUBST([DAG_LDFLAGS])
        if test -d ${withval}; then
            DAG_LDFLAGS="-L${withval}/lib"
            LDFLAGS="$DAG_LDFLAGS ${LDFLAGS}"
            CFLAGS="-I${withval}/include ${CFLAGS}"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-dag=${withval}"
        fi

        dnl look for libdag
        AC_CHECK_LIB([dag], [dag_open],
        [
            AC_DEFINE([YAF_ENABLE_DAG], [1],
                [Define to 1 to enable DAG support])
            AC_SUBST([YAF_HAS_DAG], [1])
            AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES], [1],
                [Define to 1 to enable recording interface numbers])
            interface=true
            LIBS="-ldag ${LIBS}"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-dag"
        ],[
            AC_MSG_ERROR([--with-dag given but cannot find libdag])
            dagapi=false
        ])

        AC_CHECK_HEADER([dagapi.h],
        [],[
            AC_MSG_ERROR([--with-dag given but cannot find dagapi.h])
            dagapi=false
        ])
    fi
])

dnl ----------------------------------------------------------------------
dnl Check for libpntapi
dnl ----------------------------------------------------------------------
AC_ARG_WITH([napatech],
    AS_HELP_STRING([--with-napatech[=NT_DIR]],
        [include Napatech support; find nt.h in NT_DIR/include, libntapi in NT_DIR/lib]),
[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            LDFLAGS="-L${withval}/lib ${LDFLAGS}"
            CFLAGS="-I${withval}/include ${CFLAGS} -pthread"
            CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
            LIBS="-L${withval}/lib -pthread -lntapi $LIBS"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-napatech=${withval}"
        fi
        AC_CHECK_LIB([ntapi],[NT_Init],
        [
            AC_SUBST([YAF_HAS_NAPATECH], [1])
            AC_DEFINE([YAF_ENABLE_NAPATECH], [1],
                [Define to 1 to enable Napatech support])
            AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES], [1],
                [Define to 1 to enable recording interface numbers])
            interface=true
            LIBS="-lntapi -pthread ${LIBS}"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-napatech"
            napapi=true
        ],[
            AC_MSG_ERROR([--with-napatech given but cannot find libntapi.  May need to set LDFLAGS to napatech library.])
            napapi=false
        ])
        AC_CHECK_HEADER([nt.h],
        [],[
            AC_MSG_ERROR([--with-napatech given but cannot find nt.h])
            napapi=false
        ])
    fi
])


dnl ----------------------------------------------------------------------
dnl Check for nfe_packetcap.h for Netronome support
dnl ----------------------------------------------------------------------
AC_ARG_WITH([netronome],
    AS_HELP_STRING([--with-netronome[=NFE_DIR]],
        [include Netronome API support; find nfe_packetcap.h in NFE_DIR/include]),
[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            CFLAGS="-I${withval}/include ${CFLAGS}"
            CPPFLAGS="-I{withval}/include ${CPPFLAGS}"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-netronome=${withval}"
        fi

        dnl look for libnfp
        AC_CHECK_HEADER([nfe_packetcap.h],
        [
            AC_SUBST([YAF_HAS_NETRONOME], [1])
            AC_DEFINE([YAF_ENABLE_NETRONOME], [1],
                [Define to 1 to enable Netronome support])
            AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES], [1],
                [Define to 1 to enable recording interface numbers])
            interface=true
            nfeapi=true
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-netronome"
        ],[
            AC_MSG_ERROR([--with-netronome given but cannot find nfe_packetcap.h])
            nfeapi=false
        ])
    fi
])


dnl ----------------------------------------------------------------------
dnl Check for pcap-zcopy.h
dnl ----------------------------------------------------------------------
AC_ARG_WITH([bivio],
    AS_HELP_STRING([--with-bivio[=PCAP_ZCOPY_DIR]],
        [include Bivio support; find pcap-zcopy.h in PCAP_ZCOPY_DIR/include]),
[
    if test "x$withval" != "xno"; then
        if test -d ${withval}; then
            CFLAGS="-I${withval}/include ${CFLAGS}"
        fi
        AC_CHECK_HEADERS([pcap-zcopy.h],
        [
            AC_DEFINE([YAF_ENABLE_BIVIO],[1],
                [Define to 1 to enable BIVIO support])
            AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES],[1],
                [Define to 1 to enable YAF Separate Interface Support])
            interface=true
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-bivio=${withval}"
            biviozcopy=true
        ],[
            AC_MSG_ERROR([--with-bivio given but cannot find pcap-zcopy.h])
            biviozcopy=false
        ],[
[#ifdef HAVE_PCAP_H
#include <pcap.h>
#endif
        ]])
    fi
])

dnl ----------------------------------------------------------------------
dnl Enable optional flow table features
dnl ----------------------------------------------------------------------

compact_ip4=1
AC_ARG_ENABLE([compact-ip4],
    AS_HELP_STRING([--disable-compact-ip4],
        [use full-sized IP-address data structures in the flow table [default=compact]]),
[
    if test "x$enableval" = "xno"; then
        compact_ip4=0
    fi
])
if test "x${compact_ip4}" = "x0" ; then
    AC_MSG_NOTICE([Disabling compact IPv4 address data structures in flow table])
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-compact-ip4"
else
    AC_DEFINE([YAF_ENABLE_COMPACT_IP4], [1],
        [Define to 1 to use compact IPv4 address data structures where possible])
fi

dnl ----------------------------------------------------------------------
dnl see if the user wants to enable hooks/plugins
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([plugins],
    AS_HELP_STRING([--enable-plugins],
        [enable YAF to load plugin extensions [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling plugin extension support])
        plugins=false
    else
        AC_SUBST([YAF_REQ_PLUG_CONF], [1])
        AC_DEFINE([YAF_ENABLE_HOOKS], [1],
            [Define to 1 to enable plugin support])
        plugins=true
        AC_MSG_NOTICE([Plugin extension support is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-plugins"
    fi
],[
    AC_MSG_NOTICE([Plugin extension support is disabled by default])
    plugins=false
])
AM_CONDITIONAL([PLUGINENABLE], [test x$plugins = xtrue])

dnl ----------------------------------------------------------------------
dnl Check for PCRE library, needed for the application labeler engine
dnl ----------------------------------------------------------------------
AC_SUBST([YAF_REQ_PCRE_VER], [7.3])
PKG_CHECK_MODULES([pcreLib], [libpcre >= 7.3],
[
    AC_DEFINE([HAVE_PCRE], [1], [Define to 1 to enable PCRE support])
    LDFLAGS="$LDFLAGS $pcreLib_LIBS"
    CFLAGS="$CFLAGS $pcreLib_CFLAGS"
    pcreexist=true
    AC_MSG_NOTICE([PCRE found and added to build])
    AC_SUBST([YAF_PC_PCRE], [", libpcre >= 7.3"])
],[
    AC_MSG_WARN([The application labeler engine requires the PCRE library >= 7.3 to operate, you can set the PKG_CONFIG_PATH variable to help find it. (Do you need to install pcre-devel?)])
    pcreexist=false
])
AM_CONDITIONAL([PCREEXISTS], [test x$pcreexist = xtrue])

dnl--------------------------------------------------------------------
dnl Check for OpenSSL support
dnl--------------------------------------------------------------------
AX_LIB_OPENSSL([auto],dnl
    [use OpenSSL for MD5 support [default=auto], optionally specify its installation directory])


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the application labeler
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([applabel],
    AS_HELP_STRING([--enable-applabel],
        [enable the packet payload application label engine (requires PCRE library) [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling the application labeler])
        applabeler=false
    else
        AC_DEFINE([YAF_ENABLE_APPLABEL], [1],
            [Define to 1 to enable application labeler engine])
        applabeler=true
        if test "x$pcreexist" != "xtrue"; then
            AC_MSG_ERROR([The application labeler cannot be enabled if the PCRE library is not available])
        fi
        if test "x$nopayload" == "xtrue"; then
            AC_MSG_ERROR([The application labeler cannot be enabled if payload processing is disabled])
        fi
        AC_MSG_NOTICE([Application labeler is enabled])
        AC_SUBST([YAF_REQ_PCRE], [1])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-applabel"
    fi
],[
    applabeler=false
    AC_MSG_NOTICE([Application labeler is disabled by default])
])
AM_CONDITIONAL([APPLABELENABLE], [test x$applabeler = xtrue])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of DNS Authoritative Resp ONLY
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([exportDNSAuth],
    AS_HELP_STRING([--enable-exportDNSAuth],
        [enable export of DNS Authoritative Responses Only [default=export everything]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Enabling export of all DNS Responses])
        exportDNSAuth = false
    else
        AC_DEFINE([YAF_ENABLE_DNSAUTH], [1],
            [Define to 1 to enable export of DNS Authoritative Responses Only])
        exportDNSAuth=true
        if test "x$plugins" != "xtrue"; then
            AC_MSG_ERROR([DNS Authoritative Response Export requires plugins to be enabled])
        fi
        if test "x$applabeler" != "xtrue"; then
            AC_MSG_ERROR([Application labeling must be enabled to export DNS Authoritative Responses])
        fi
        AC_MSG_NOTICE([Export only DNS Authoritative Responses is enabled])
    fi
],[
    exportDNSAuth=false
    AC_MSG_NOTICE([Enable Export of DNS Authoritative Responses is disabled by default])
])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of DNS NXDOMAIN Responses ONLY
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([exportDNSNXDomain],
    AS_HELP_STRING([--enable-exportDNSNXDomain],
        [enable export of DNS NXDomain Responses Only [default=export everything]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Enabling export of all DNS Responses])
        exportDNSNXDomain = false
    else
        AC_DEFINE([YAF_ENABLE_DNSNXDOMAIN], [1],
            [Define to 1 to enable export of DNS NXDomain Responses Only])
        exportDNSNXDomain=true
        if test "x$plugins" != "xtrue"; then
            AC_MSG_ERROR([DNS NXDomain Response Export requires plugins to be enabled])
        fi
        if test "x$applabeler" != "xtrue"; then
            AC_MSG_ERROR([Application labeling must be enabled to export DNS Authoritative Responses])
        fi
        AC_MSG_NOTICE([Export only DNS NXDomain Responses is enabled])
    fi
],[
    exportDNSNXDomain=false
    AC_MSG_NOTICE([Enable Export of DNS NXDomain Responses is disabled by default])
])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the entropy calculator
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([entropy],
    AS_HELP_STRING([--enable-entropy],
        [enable the packet payload entropy calculation [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling the entropy calculator])
        entropycalc=false
    else
        AC_DEFINE([YAF_ENABLE_ENTROPY], [1],
            [Define to 1 to enable entropy calculator])
        entropycalc=true
        if test "x$nopayload" == "xtrue"; then
            AC_MSG_ERROR([The entropy calculator cannot be enabled if payload processing is disabled])
        fi
        AC_MSG_NOTICE([Entropy calculator is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-entropy"
    fi
],[
    AC_MSG_NOTICE([Entropy calculator disabled by default])
    entropycalc=false
])


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the DAG interface hack
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([daginterface],
    AS_HELP_STRING([--enable-daginterface],
        [enable encoding DAG interface numbers into the record output [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling the DAG interface numbers recording])
        daginterfacehack=false
    else
        AC_DEFINE([YAF_ENABLE_DAG_SEPARATE_INTERFACES], [1],
            [Define to 1 to enable recording DAG interface numbers])
        daginterfacehack=true
        AC_MSG_NOTICE([DAG interface recording into output records is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-daginterface"
    fi
],[
    AC_MSG_NOTICE([DAG interface recording into output record disabled by default])
    daginterfacehack=false
])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the Napatech interface hack
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([interface],
    AS_HELP_STRING([--enable-interface],
        [enable encoding Napatech/Netronome/DAG interface numbers into the record output [default=yes]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling the interface numbers recording])
        interface=false
    else
        AC_DEFINE([YAF_ENABLE_SEPARATE_INTERFACES], [1],
            [Define to 1 to enable recording interface numbers])
        interface=true
        AC_MSG_NOTICE([Interface recording into output records is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-interface"
    fi
])


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of handshake headers
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([fpexporter],
    AS_HELP_STRING([--enable-fpexporter],
        [enable export of handshake headers for external fingerprinting [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling the fingerprint exporter])
        fp_exporter = false
    else
        AC_DEFINE([YAF_ENABLE_FPEXPORT], [1],
            [Define to 1 to enable fingerprint exporter])
        fp_exporter=true
        if test "x$nopayload" == "xtrue"; then
            AC_MSG_ERROR([The fpexporter cannot be enabled if payload processing is disabled])
        fi
        AC_MSG_NOTICE([Fingerprint exporter is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-fpexporter"
    fi
],[
    fp_exporter=false
    AC_MSG_NOTICE([fingerprint exporter disabled by default])
])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the p0f based finger printer
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([p0fprinter],
    AS_HELP_STRING([--enable-p0fprinter],
        [enable the p0f based OS finger printing capability (requires libp0f) [default=no]]),
[
    if test "x$enableval" != "xno"; then
        if test "x$applabeler" != "xtrue"; then
            AC_MSG_ERROR([The p0f finger printer cannot be enabled if the application labeler is not also enabled])
        fi
        if test "x$nopayload" == "xtrue"; then
            AC_MSG_ERROR([The application labeler cannot be enabled if payload processing is disabled])
        fi

        PKG_CHECK_MODULES([libp0f], [libp0f >= 2.0.8],
        [],[
            AC_MSG_ERROR([Cannot find a suitable libp0f (>= 2.0.8) (Try setting PKG_CONFIG_PATH): $libp0f_PKG_ERRORS])
        ])

        AC_SUBST([YAF_REQ_P0F_VER], [2.0.8])
        AC_DEFINE([YAF_ENABLE_P0F], [1],
            [Define to 1 to enable p0f OS fingerprinter])
        p0f_printer=true
        AC_MSG_NOTICE([p0f based OS finger printer is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-p0fprinter"
    fi
],[
    p0f_printer=false
    AC_MSG_NOTICE([p0f based OS fingerprinter disabled by default])
])
AM_CONDITIONAL([P0FENABLE], [test x$p0f_printer = xtrue])


dnl ----------------------------------------------------------------------
dnl check if the user wants to support MPLS netflow
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([mpls],
    AS_HELP_STRING([--enable-mpls],
        [enable MPLS label hashing and export [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling MPLS support])
        mpls=false
    else
        AC_DEFINE([YAF_MPLS], [1], [Define to 1 to enable mpls support])
        mpls=true
        AC_MSG_NOTICE([MPLS Flow is enabled])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-mpls"
    fi
],[
    mpls=false
    AC_MSG_NOTICE([MPLS Flow is disabled by default])
])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable non-IP flow data
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([nonip],
    AS_HELP_STRING([--enable-nonip],
        [enable non-IP data decode and flow export (requires mpls) [default=no]]),
[
    if test "x$enableval" = "xno"; then
        AC_MSG_NOTICE([Disabling Non-IP flow data])
        nonip=false
    else
        AC_DEFINE([YAF_NONIP], [1],
            [Define to 1 to enable non-IP flow data export])
        if test "x$mpls" != "xtrue"; then
            AC_MSG_ERROR([Non-IP data decode and flow export requires --enable-mpls])
        fi
        nonip=true
        AC_MSG_NOTICE([Enabling NON-IP data decode and export])
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-nonip"
    fi
],[
    nonip=false
    AC_MSG_NOTICE([Non-IP Flow is disabled by default])
])

dnl ----------------------------------------------------------------------
dnl check for disabling export of type information via (RFC 5610) and
dnl template metadata information
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE([type-export],
    AS_HELP_STRING([--disable-type-export],
        [disable exporting of options records for enterprise-specific information elements and template metadata]),
[
    if test "x$enableval" = "xno"; then
        type_export=false
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-type-export"
        AC_MSG_NOTICE([type export is disabled])
    else
        AC_MSG_NOTICE([type export is not disabled])
        type_export=true
        AC_DEFINE([YAF_ENABLE_METADATA_EXPORT], [1],
            [Define to 1 to enable yaf metadata export])
    fi
],[
    AC_DEFINE([YAF_ENABLE_METADATA_EXPORT], [1],
        [Define to 1 to enable yaf metadata export])
    AC_MSG_NOTICE([Metadata export is enabled by default])
    type_export=true
])

dnl ----------------------------------------------------------------------
dnl Check for Spread Support
dnl ----------------------------------------------------------------------
AC_PATH_SPREAD([4.1])
if test "x$ac_cv_header_spread_sp_h" == "xyes"; then
    AC_SUBST([FIXBUF_REQ_LIBSPREAD], [1])
fi

dnl -------------------------------------------------------------------
dnl  Use the local timezone for command inputs and printing records
dnl -------------------------------------------------------------------
ENABLE_LOCALTIME=0
AC_ARG_ENABLE([localtime],
    AS_HELP_STRING([--enable-localtime],
        [use the local timezone for command inputs and for printing records.  Default is to use UTC.  (Flows are always exported in UTC time.)]),
[
    if test "x$enableval" = "xyes"
    then
        ENABLE_LOCALTIME=1
        AC_MSG_NOTICE([Local timezone support is enabled])
    fi
])

AC_DEFINE_UNQUOTED([ENABLE_LOCALTIME], [$ENABLE_LOCALTIME],
     [Define to 1 to use the local timezone for command input and
     printing records.  Define to 0 to use UTC.])


dnl ----------------------------------------------------------------------
dnl Check for Unix vs. Linux privdrop (EWW EWW HACK EWW)
dnl ----------------------------------------------------------------------
if test "x$target_os" = "xlinux" -o \
        "x$target_os" = "xlinux-gnu"; then
    AC_MSG_NOTICE([Enabling Linux privilege drop hack])
    AC_DEFINE([LINUX_PRIVHACK], [1],
              [Define to 1 on Linux for privilege drop hack])
else
    AC_MSG_NOTICE([Normal privilege drop (target os is $target_os)])
fi

dnl ----------------------------------------------------------------------
dnl Check if this is Solaris and enabled the impure-text option
dnl ----------------------------------------------------------------------
case $target_os in
        solaris*) LDFLAGS="$LDFLAGS -mimpure-text" ;;
esac

dnl ----------------------------------------------------------------------
dnl Add a conditional flag into Automake for Cygwin checking
dnl ----------------------------------------------------------------------
AM_CONDITIONAL([CYGWIN], [test "x$target_os" = "xcygwin"])

dnl ---------------------------------------------------------------------
dnl Check for decompression support
dnl ---------------------------------------------------------------------
AX_CHECK_LIBZ

dnl ----------------------------------------------------------------------
dnl Determine infomodel information
dnl ----------------------------------------------------------------------
AM_MISSING_PROG([XSLTPROC], [xsltproc])
INFOMODEL_AC_COLLECT_REGISTRIES([infomodel])
AC_PATH_PROG([PERL], [perl])


dnl ----------------------------------------------------------------------
dnl Write Makefiles (and all the other files too)
dnl ----------------------------------------------------------------------
AC_SUBST([LIBCOMPAT])
AC_SUBST([RPM_CONFIG_FLAGS])


dnl automake 1.9 doesn't substitute these automatically, so we do it ourselves
dnl just in case
AC_SUBST([abs_top_srcdir])
AC_SUBST([abs_top_builddir])

YAF_AC_WRITE_SUMMARY

AC_CONFIG_FILES([
    Makefile
    src/Makefile
    include/Makefile
    infomodel/Makefile
    etc/Makefile
    scripts/Makefile
    src/applabel.pod
    src/yafdpi.pod
    src/applabel/Makefile
    src/applabel/plugins/Makefile
    src/applabel/hooks/Makefile
    doc/Makefile
    src/yaf.pod
    libyaf.pc
    etc/init.d/yaf
    yaf.spec
    Doxyfile
    README
    etc/yaf.conf
    airframe/Makefile
    airframe/src/Makefile
    airframe/include/Makefile
    airframe/doc/Makefile
    airframe/libairframe.pc
])
##  AC_CONFIG_FILES that are not currently used:
##
##  airframe/Doxyfile 
##  airframe/libairframe.spec

AC_OUTPUT
