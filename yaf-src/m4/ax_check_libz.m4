dnl Copyright (C) 2004-2023 by Carnegie Mellon University.
dnl See license information in LICENSE.txt.

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

# ---------------------------------------------------------------------------
# AX_CHECK_LIBZ
#
#    Determine how to use the zlib (gzip) compression library
#
#    Output defines: YAF_ENABLE_ZLIB

AC_DEFUN([AX_CHECK_LIBZ],[
    ENABLE_ZLIB=0

    AC_ARG_WITH([zlib],[AS_HELP_STRING([--with-zlib=ZLIB_DIR],
            [specify location of the zlib file compression library; find "zlib.h" in ZLIB_DIR/include/; find "libz.so" in ZLIB_DIR/lib/ [auto]])[]dnl
        ],[
            if test "x$withval" != "xyes"
            then
                zlib_dir="$withval"
                zlib_includes="$zlib_dir/include"
                zlib_libraries="$zlib_dir/lib"
            fi
    ])
    AC_ARG_WITH([zlib-includes],[AS_HELP_STRING([--with-zlib-includes=DIR],
            [find "zlib.h" in DIR/ (overrides ZLIB_DIR/include/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                zlib_dir=no
            elif test "x$withval" != "xyes"
            then
                zlib_includes="$withval"
            fi
    ])
    AC_ARG_WITH([zlib-libraries],[AS_HELP_STRING([--with-zlib-libraries=DIR],
            [find "libz.so" in DIR/ (overrides ZLIB_DIR/lib/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                zlib_dir=no
            elif test "x$withval" != "xyes"
            then
                zlib_libraries="$withval"
            fi
    ])

    if test "x$zlib_dir" != "xno"
    then
        # Cache current values
        yf_save_LDFLAGS="$LDFLAGS"
        yf_save_LIBS="$LIBS"
        yf_save_CFLAGS="$CFLAGS"
        yf_save_CPPFLAGS="$CPPFLAGS"

        if test "x$zlib_libraries" != "x"
        then
            ZLIB_LDFLAGS="-L$zlib_libraries"
            LDFLAGS="$ZLIB_LDFLAGS $yf_save_LDFLAGS"
        fi

        if test "x$zlib_includes" != "x"
        then
            ZLIB_CFLAGS="-I$zlib_includes"
            CPPFLAGS="$ZLIB_CFLAGS $yf_save_CPPFLAGS"
        fi

        AC_CHECK_LIB([z], [gzopen],
            [ENABLE_ZLIB=1 ; ZLIB_LDFLAGS="$ZLIB_LDFLAGS -lz"])

        if test "x$ENABLE_ZLIB" = "x1"
        then
            AC_CHECK_HEADER([zlib.h], , [
                AC_MSG_WARN([Found libz but not zlib.h.  Maybe you should install zlib-devel?])
                ENABLE_ZLIB=0])
        fi

        # Restore cached values
        LDFLAGS="$yf_save_LDFLAGS"
        LIBS="$yf_save_LIBS"
        CFLAGS="$yf_save_CFLAGS"
        CPPFLAGS="$yf_save_CPPFLAGS"
    fi

    if test "x$ENABLE_ZLIB" != "x1"
    then
        ZLIB_CFLAGS=
        ZLIB_LDFLAGS=
    else
        LIBS="$LIBS $ZLIB_LDFLAGS"
        CFLAGS="$ZLIB_CFLAGS $CFLAGS"

        AC_DEFINE([YAF_ENABLE_ZLIB], [1],
            [Define to 1 build with support for zlib compression.  Requires the libz library and the <zlib.h> header file.])
    fi
])# AX_CHECK_LIBZ

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
