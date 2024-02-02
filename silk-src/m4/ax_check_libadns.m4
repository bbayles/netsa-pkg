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

dnl RCSIDENT("$SiLK: ax_check_libadns.m4 b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")

# ---------------------------------------------------------------------------
# AX_CHECK_LIBADNS
#
#    Try to find the ADNS (Asynchronous DNS) library.
#
#    Output variables: ADNS_CFLAGS ADNS_LDFLAGS
#    Output definition: HAVE_ADNS_H
#
AC_DEFUN([AX_CHECK_LIBADNS],[
    AC_SUBST(ADNS_CFLAGS)
    AC_SUBST(ADNS_LDFLAGS)

    AC_ARG_WITH([adns],[AS_HELP_STRING([--with-adns=ADNS_DIR],
            [specify location of the ADNS asynchronous DNS library; find "adns.h" in ADNS_DIR/include/; find "libadns.so" in ADNS_DIR/lib/ [auto]])[]dnl
        ],[
            if test "x$withval" != "xyes"
            then
                adns_dir="$withval"
                adns_includes="$adns_dir/include"
                adns_libraries="$adns_dir/lib"
            fi
    ])
    AC_ARG_WITH([adns-includes],[AS_HELP_STRING([--with-adns-includes=DIR],
            [find "adns.h" in DIR/ (overrides ADNS_DIR/include/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                adns_dir=no
            elif test "x$withval" != "xyes"
            then
                adns_includes="$withval"
            fi
    ])
    AC_ARG_WITH([adns-libraries],[AS_HELP_STRING([--with-adns-libraries=DIR],
            [find "libadns.so" in DIR/ (overrides ADNS_DIR/lib/)])[]dnl
        ],[
            if test "x$withval" = "xno"
            then
                adns_dir=no
            elif test "x$withval" != "xyes"
            then
                adns_libraries="$withval"
            fi
    ])

    ENABLE_ADNS=0
    if test "x$adns_dir" != "xno"
    then
        # Cache current values
        sk_save_LDFLAGS="$LDFLAGS"
        sk_save_LIBS="$LIBS"
        sk_save_CFLAGS="$CFLAGS"
        sk_save_CPPFLAGS="$CPPFLAGS"

        if test "x$adns_libraries" != "x"
        then
            ADNS_LDFLAGS="-L$adns_libraries"
            LDFLAGS="$ADNS_LDFLAGS $sk_save_LDFLAGS"
        fi

        if test "x$adns_includes" != "x"
        then
            ADNS_CFLAGS="-I$adns_includes"
            CPPFLAGS="$ADNS_CFLAGS $sk_save_CPPFLAGS"
        fi

        AC_CHECK_LIB([adns], [adns_init],
            [ENABLE_ADNS=1 ; ADNS_LDFLAGS="$ADNS_LDFLAGS -ladns"])

        if test "x$ENABLE_ADNS" = "x1"
        then
            AC_CHECK_HEADER([adns.h], , [
                AC_MSG_WARN([Found libadns but not adns.h.  Maybe you should install adns-devel?])
                ENABLE_ADNS=0])
        fi

        if test "x$ENABLE_ADNS" = "x1"
        then
            AC_MSG_CHECKING([usability of ADNS library and headers])
            LDFLAGS="$sk_save_LDFLAGS"
            LIBS="$ADNS_LDFLAGS $sk_save_LIBS"
            AC_LINK_IFELSE(
                [AC_LANG_PROGRAM([
#include <adns.h>
                    ],[
adns_state adns;
adns_query q;
int rv;

rv = adns_init(&adns, (adns_initflags)0, 0);
rv = adns_submit(adns, "255.255.255.255.in-addr.arpa", adns_r_ptr,
                 (adns_queryflags)(adns_qf_quoteok_cname|adns_qf_cname_loose),
                 NULL, &q);
                     ])],[
                AC_MSG_RESULT([yes])],[
                AC_MSG_RESULT([no])
                ENABLE_ADNS=0])
        fi

        # Restore cached values
        LDFLAGS="$sk_save_LDFLAGS"
        LIBS="$sk_save_LIBS"
        CFLAGS="$sk_save_CFLAGS"
        CPPFLAGS="$sk_save_CPPFLAGS"
    fi

    if test "x$ENABLE_ADNS" != "x1"
    then
        ADNS_LDFLAGS=
        ADNS_CFLAGS=
    else
        AC_DEFINE([HAVE_ADNS_H], 1,
            [Define to 1 include support for ADNS (asynchronous DNS).
             Requires the ADNS library and the <adns.h> header file.])
    fi
])# AX_CHECK_LIBADNS

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
