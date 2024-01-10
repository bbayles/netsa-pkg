dnl Copyright (C) 2011-2023 by Carnegie Mellon University.
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

dnl RCSIDENT("$SiLK: ax_check_printf_z.m4 b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")

# ---------------------------------------------------------------------------
# AX_CHECK_PRINTF_Z
#
#    Determine what format string to use for size_t and ssize_t
#
AC_DEFUN([AX_CHECK_PRINTF_Z],[
    AC_MSG_CHECKING([whether printf understands the "z" modifier])
    sk_save_CFLAGS="${CFLAGS}"
    CFLAGS="${WARN_CFLAGS} ${sk_werror} ${CFLAGS}"
    AC_COMPILE_IFELSE([
        AC_LANG_PROGRAM([[
#include <stdio.h>
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef    STDC_HEADERS
#  include <stdlib.h>
#  include <stddef.h>
#else
#  ifdef  HAVE_STDLIB_H
#    include <stdlib.h>
#  endif
#  ifdef  HAVE_MALLOC_H
#    include <malloc.h>
#  endif
#endif
#ifdef    HAVE_STRING_H
#  if     !defined STDC_HEADERS && defined HAVE_MEMORY_H
#    include <memory.h>
#  endif
#  include <string.h>
#endif
#ifdef    HAVE_STRINGS_H
#  include <strings.h>
#endif
            ]], [[
char a[128];
char b[128];
size_t s = (size_t)0xfedcba98;
sprintf(a, "%zu", s);
sprintf(b, "%lu", (unsigned long)s);
return strcmp(a, b);
            ]])
    ],[
         AC_MSG_RESULT([yes])
         AC_DEFINE([HAVE_PRINTF_Z_FORMAT], [1], [Define to 1 if printf supports the "z" modifier])
    ],[
         AC_MSG_RESULT([no])
    ],[
         AC_MSG_RESULT([assuming no])
    ])
    CFLAGS="${sk_save_CFLAGS}"
])# AX_CHECK_PRINTF_Z

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
