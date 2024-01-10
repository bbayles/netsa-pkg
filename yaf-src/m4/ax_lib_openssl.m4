dnl -*- mode: autoconf -*-
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
# AX_LIB_OPENSSL
#
#   Check for the OpenSSL library (-lssl -lcrypt) and header files.
#
#   Expects two arguments:
#
#   1. First should be "yes", "no", or "auto". "yes" means to fail if OpenSSL
#   cannot be found unless the user explicitly disables it.  "no" means only
#   use OpenSSL when requested by the user. "auto" (or any other value) means
#   to check for OpenSSL unless disabled by the user, but do not error if it
#   is not found.
#
#   2. Second is the help string to print for the --with-openssl argument.
#
#   Output definitions: HAVE_EVP_MD5, HAVE_EVP_MD_FETCH, HAVE_EVP_Q_DIGEST,
#   HAVE_EVP_SHA1, HAVE_EVP_SHA256, HAVE_MD5, HAVE_OPENSSL,
#   HAVE_OPENSSL_EVP_H, HAVE_OPENSSL_MD5_H, HAVE_OPENSSL_SHA_H, HAVE_SHA1,
#   HAVE_SHA256
#
AC_DEFUN([AX_LIB_OPENSSL],[
    default="$1"
    m4_define(openssl_helpstring,[[$2]])

    AC_SUBST([OPENSSL_CPPFLAGS])
    AC_SUBST([OPENSSL_LDFLAGS])

    YF_HAVE_OPENSSL=

    if test "x${default}" = xyes
    then
        request_require=required
    else
        request_require=requested
    fi

    AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--with-openssl@<:@=PREFIX@:>@],dnl
        openssl_helpstring)],[],
    [
        # Option not given, use default
        if test "x${default}" = xyes || test "x${default}" = xno
        then
            with_openssl="${default}"
        fi
    ])

    if test "x${with_openssl}" = xno
    then
        AC_MSG_NOTICE([not checking for OpenSSL])
    else
        yaf_save_CPPFLAGS="${CPPFLAGS}"
        yaf_save_LDFLAGS="${LDFLAGS}"
        yaf_save_LIBS="${LIBS}"

        AC_MSG_NOTICE([checking for OpenSSL...])
        if test -n "${with_openssl}" && test "x${with_openssl}" != xyes ; then
            OPENSSL_CPPFLAGS="-I${with_openssl}/include"
            OPENSSL_LDFLAGS="-L${with_openssl}/lib"

            CPPFLAGS="${OPENSSL_CPPFLAGS} ${CPPFLAGS}"
            LDFLAGS="${OPENSSL_LDFLAGS} ${LDFLAGS}"
        fi

        dnl look for libssl
        AC_CHECK_LIB([crypto], [EVP_Digest],
        [
            YF_HAVE_OPENSSL=yes
            AC_DEFINE(HAVE_OPENSSL, 1, [Define to 1 to enable OpenSSL support])
            OPENSSL_LDFLAGS="${OPENSSL_LDFLAGS} -lssl -lcrypto"
            LIBS="-lssl -lcrypto ${LIBS}"

            # Additional functions to check for; no error
            AC_CHECK_FUNCS([EVP_Q_digest EVP_MD_fetch EVP_md5 EVP_sha1 EVP_sha256 MD5 SHA1 SHA256])

            AC_CHECK_HEADERS([openssl/evp.h],[],
            [
                if test "x${with_openssl}" != x
                then
                    AC_MSG_ERROR([OpenSSL support ${request_require} but cannot find openssl/evp.h])
                fi
            ])

            # Additional headers to check for; no error
            AC_CHECK_HEADERS([openssl/sha.h openssl/md5.h])
        ],[
            if test "x${with_openssl}" != x
            then
                AC_MSG_ERROR([OpenSSL support ${request_require} but cannot find EVP_Digest()])
            fi
        ])

        # remove spaces
        OPENSSL_LDFLAGS=`echo "${OPENSSL_LDFLAGS}" | sed 's/^ *//' | sed 's/  */ /g'`

        if test "x${YF_HAVE_OPENSSL}" = xyes
        then
            AC_MSG_NOTICE([building with OpenSSL support])
        else
            AC_MSG_NOTICE([not building with OpenSSL support])
            OPENSSL_CPPFLAGS=
            OPENSSL_LDFLAGS=
        fi

        CPPFLAGS="${yaf_save_CPPFLAGS}"
        LDFLAGS="${yaf_save_LDFLAGS}"
        LIBS="${yaf_save_LIBS}"
    fi
])
