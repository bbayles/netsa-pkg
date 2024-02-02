dnl Copyright (C) 2004-2023 by Carnegie Mellon University.
dnl
dnl @OPENSOURCE_LICENSE_START@
dnl
dnl SiLK 3.22.0
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
dnl Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
dnl contact permission@sei.cmu.edu for full terms.
dnl
dnl [DISTRIBUTION STATEMENT A] This material has been approved for public
dnl release and unlimited distribution.  Please see Copyright notice for
dnl non-US Government use and distribution.
dnl
dnl GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
dnl
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
dnl Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
dnl Trademark Office by Carnegie Mellon University.
dnl
dnl This Software includes and/or makes use of Third-Party Software each
dnl subject to its own license.
dnl
dnl DM23-0973
dnl
dnl @OPENSOURCE_LICENSE_END@

dnl RCSIDENT("$SiLK: ax_check_libsnappy.m4 b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")

# ---------------------------------------------------------------------------
# AX_CHECK_LIBSNAPPY
#
#    Determine how to use the snappy compression library
#
#    Substitutions: SK_ENABLE_SNAPPY
#    Output defines: ENABLE_SNAPPY
#
AC_DEFUN([AX_CHECK_LIBSNAPPY],[
    ENABLE_SNAPPY=0

    AC_ARG_WITH([snappy],[AS_HELP_STRING([--with-snappy=SNAPPY_DIR],
            [specify location of the snappy file compression library; find "snappy-c.h" in SNAPPY_DIR/include/; find "libsnappy.so" in SNAPPY_DIR/lib/ [auto]])[]dnl
        ],[
            if test "x$withval" != "xyes"
            then
                snappy_dir="$withval"
                snappy_includes="$snappy_dir/include"
                snappy_libraries="$snappy_dir/lib"
            fi
    ])
    AC_ARG_WITH([snappy-includes],[AS_HELP_STRING([--with-snappy-includes=DIR],
            [find "snappy-c.h" in DIR/ (overrides SNAPPY_DIR/include/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                snappy_dir=no
            elif test "x$withval" != "xyes"
            then
                snappy_includes="$withval"
            fi
    ])
    AC_ARG_WITH([snappy-libraries],[AS_HELP_STRING([--with-snappy-libraries=DIR],
            [find "libsnappy.so" in DIR/ (overrides SNAPPY_DIR/lib/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                snappy_dir=no
            elif test "x$withval" != "xyes"
            then
                snappy_libraries="$withval"
            fi
    ])

    if test "x$snappy_dir" != "xno"
    then
        # Cache current values
        sk_save_LDFLAGS="$LDFLAGS"
        sk_save_LIBS="$LIBS"
        sk_save_CFLAGS="$CFLAGS"
        sk_save_CPPFLAGS="$CPPFLAGS"

        if test "x$snappy_libraries" != "x"
        then
            SNAPPY_LDFLAGS="-L$snappy_libraries"
            LDFLAGS="$SNAPPY_LDFLAGS $sk_save_LDFLAGS"
        fi

        if test "x$snappy_includes" != "x"
        then
            SNAPPY_CFLAGS="-I$snappy_includes"
            CPPFLAGS="$SNAPPY_CFLAGS $sk_save_CPPFLAGS"
        fi

        AC_CHECK_LIB([snappy], [snappy_compress],
            [ENABLE_SNAPPY=1 ; SNAPPY_LDFLAGS="$SNAPPY_LDFLAGS -lsnappy"])

        if test "x$ENABLE_SNAPPY" = "x1"
        then
            AC_CHECK_HEADER([snappy-c.h], , [
                AC_MSG_WARN([Found snappy but not snappy-c.h.  Maybe you should install snappy-devel?])
                ENABLE_SNAPPY=0])
        fi

        # Restore cached values
        LDFLAGS="$sk_save_LDFLAGS"
        LIBS="$sk_save_LIBS"
        CFLAGS="$sk_save_CFLAGS"
        CPPFLAGS="$sk_save_CPPFLAGS"
    fi

    if test "x$ENABLE_SNAPPY" != "x1"
    then
        SNAPPY_CFLAGS=
        SNAPPY_LDFLAGS=
    fi

    AC_DEFINE_UNQUOTED([ENABLE_SNAPPY], [$ENABLE_SNAPPY],
        [Define to 1 build with support for snappy compression.  Define
         to 0 otherwise.  Requires the libsnappy library and the
         snappy-c.h header file.])
    AC_SUBST([SK_ENABLE_SNAPPY], [$ENABLE_SNAPPY])
])# AX_CHECK_SNAPPY

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
