dnl -*- mode: autoconf -*-
dnl Copyright (C) 2006-2023 by Carnegie Mellon University.
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

dnl ax_enable_warnings.m4
dnl
dnl Determines the compiler flags to use for warnings.  User may use
dnl --enable-warnings to provide their own or override the default.
dnl
dnl OUTPUT VARIABLE:  WARN_CFLAGS
dnl
AC_DEFUN([AX_ENABLE_WARNINGS],[
    AC_SUBST([WARN_CFLAGS])

    WARN_CFLAGS=
    default_warn_flags="-Wall -Wextra -Wshadow -Wpointer-arith -Wformat=2 -Wunused -Wduplicated-cond -Wwrite-strings -Wmissing-prototypes -Wstrict-prototypes"
    # YAF has too many unused parameters. Disable that warning until
    # they can be marked as unused.
    default_warn_flags="${default_warn_flags} -Wno-unused-parameter"
    # YAF and fixbuf 2 use #if instead of #ifdef for autoconf-defined
    # macros. Disable that warning.
    #default_warn_flags="${default_warn_flags} -Wunused"


    AC_ARG_ENABLE([warnings],
    [AS_HELP_STRING([[--enable-warnings[=FLAGS]]],dnl
        [enable compile-time warnings [default=yes]; if value given, use those compiler warnings instead of default])],
    [
        if test "X${enable_warnings}" = Xno
        then
            AC_MSG_NOTICE([disabled all compiler warning flags])
        elif test "X${enable_warnings}" != Xyes
        then
            WARN_CFLAGS="${enable_warnings}"
        fi
    ],[
        enable_warnings=yes
    ])

    if test "x${enable_warnings}" = xyes
    then
        save_cflags="${CFLAGS}"
        for f in ${default_warn_flags} ; do
            AC_MSG_CHECKING([whether ${CC} supports ${f}])
            CFLAGS="${save_cflags} -Werror ${f}"
            AC_COMPILE_IFELSE([
                AC_LANG_PROGRAM([[@%:@include <stdio.h>]],[[
                    printf("Hello, World\n");
                ]])
            ],[
                AC_MSG_RESULT([yes])
                WARN_CFLAGS="${WARN_CFLAGS} ${f}"
            ],[
                AC_MSG_RESULT([no])
            ])
        done
        CFLAGS="${save_cflags}"
    fi

])
