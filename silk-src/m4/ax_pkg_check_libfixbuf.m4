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

dnl RCSIDENT("$SiLK: ax_pkg_check_libfixbuf.m4 b2b562f1ea39 2023-02-20 17:50:25Z mthomas $")


# ---------------------------------------------------------------------------
# AX_PKG_CHECK_LIBFIXBUF
#
#    Determine how to use the fixbuf library.  Function accepts two
#    arguments (requires 1): minimum allowed version and too-new
#    version.
#
#    Output variables:  FIXBUF_CFLAGS, FIXBUF_LDFLAGS,
#    Output definition: ENABLE_IPFIX
#
AC_DEFUN([AX_PKG_CHECK_LIBFIXBUF],[
    AC_SUBST([FIXBUF_CFLAGS])
    AC_SUBST([FIXBUF_LDFLAGS])

    # Either one or two arguments; first is minimum version required;
    # if a second is present, it represents a version that is "too
    # new"
    libfixbuf_required_version="$1"
    if test "x$2" = "x"
    then
        version_check="libfixbuf >= $1"
    else
        version_check="libfixbuf >= $1 libfixbuf < $2"
    fi

    # the value in libfixbuf_have_version is printed as part of the
    # package summary
    libfixbuf_have_version=no

    ENABLE_IPFIX=0

    # whether to exit with an error if building without libfixbuf.
    # this is set to true when --with-libfixbuf is given and its
    # argument is not "no"
    sk_withval_used=false

    # The configure switch
    sk_pkg_config=""
    AC_ARG_WITH([libfixbuf],[AS_HELP_STRING([--with-libfixbuf=DIR],
            [specify location of the libfixbuf IPFIX protocol package; find "libfixbuf.pc" in the directory DIR/ (i.e., prepend DIR to PKG_CONFIG_PATH).  The last component of DIR is likely "pkgconfig" [auto]])[]dnl
        ],[
            case "x${withval}" in
            xno)  sk_pkg_config="${withval}"  ;;
            xyes) sk_withval_used=true        ;;
            *)    sk_pkg_config="${withval}"  sk_withval_used=true ;;
            esac
    ])

    if test "x${sk_pkg_config}" = "xno"
    then
        AC_MSG_NOTICE([Building without IPFIX support at user request])
    else
        if test "x${sk_pkg_config}" != "x"
        then
            # prepend the argument to PKG_CONFIG_PATH, and warn when
            # that argument does not end with "/pkgconfig"
            sk_save_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
            PKG_CONFIG_PATH="${sk_pkg_config}:${PKG_CONFIG_PATH}"
            export PKG_CONFIG_PATH

            if expr "x${sk_pkg_config}" : '.*/pkgconfig$' > /dev/null
            then
                :
            else
                AC_MSG_WARN([Argument to --with-libfixbuf should probably end with '/pkgconfig'])
            fi
        fi

        # use pkg-config to check for libfixbuf existence
        echo "${as_me}:${LINENO}: Using PKG_CONFIG_PATH='${PKG_CONFIG_PATH}'" >&AS_MESSAGE_LOG_FD
        PKG_CHECK_MODULES([LIBFIXBUF],
            [${version_check}],
            [ENABLE_IPFIX=1],[ENABLE_IPFIX=0])
        if test "x${ENABLE_IPFIX}" = "x0"
        then
            AC_MSG_NOTICE([Building without IPFIX support: pkg-config failed to find libfixbuf])
            if ${sk_withval_used}
            then
                AC_MSG_ERROR([unable to use libfixbuf; fix or remove --with-libfixbuf switch])
            fi
        else
            # verify that libfixbuf has any packages it depends on
            sk_pkg_modversion=`${PKG_CONFIG} --modversion libfixbuf 2>/dev/null`
            if test "x${sk_pkg_modversion}" = "x"
            then
                # PKG_CHECK_MODULES() says package is available, but
                # pkg-config does not find it; assume the user set the
                # LIBFIXBUF_LIBS/LIBFIXBUF_CFLAGS variables
                sk_pkg_modversion=unknown
            else
                AC_MSG_CHECKING([presence of libfixbuf-${sk_pkg_modversion} dependencies])
                echo "${as_me}:${LINENO}: \$PKG_CONFIG --libs libfixbuf >/dev/null 2>&AS_MESSAGE_LOG_FD" >&AS_MESSAGE_LOG_FD
                (${PKG_CONFIG} --libs libfixbuf) >/dev/null 2>&AS_MESSAGE_LOG_FD
                sk_pkg_status=$?
                echo "${as_me}:${LINENO}: \$? = ${sk_pkg_status}" >&AS_MESSAGE_LOG_FD

                if test 0 -eq ${sk_pkg_status}
                then
                    AC_MSG_RESULT([yes])
                else
                    AC_MSG_RESULT([no])
                    AC_MSG_NOTICE([Building without IPFIX support: pkg-config failed to find dependencies for libfixbuf. Details in config.log.])
                    if ${sk_withval_used}
                    then
                        AC_MSG_ERROR([unable to use libfixbuf; fix or remove --with-libfixbuf switch])
                    fi
                    ENABLE_IPFIX=0
                fi
            fi
        fi

        # Restore the PKG_CONFIG_PATH to the saved value
        if test "x${sk_pkg_config}" != "x"
        then
            PKG_CONFIG_PATH="${sk_save_PKG_CONFIG_PATH}"
            export PKG_CONFIG_PATH
        fi
    fi

    # compile program that uses libfixbuf
    if test "x${ENABLE_IPFIX}" = "x1"
    then
        # Cache current values
        sk_save_LDFLAGS="${LDFLAGS}"
        sk_save_LIBS="${LIBS}"
        sk_save_CFLAGS="${CFLAGS}"
        sk_save_CPPFLAGS="${CPPFLAGS}"

        FIXBUF_LDFLAGS="${LIBFIXBUF_LIBS}"
        LIBS="${FIXBUF_LDFLAGS} ${LIBS}"

        FIXBUF_CFLAGS="${LIBFIXBUF_CFLAGS}"
        CPPFLAGS="${FIXBUF_CFLAGS} ${CPPFLAGS}"

        AC_MSG_CHECKING([usability of libfixbuf-${sk_pkg_modversion} library and headers])
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([
#include <fixbuf/public.h>
                ],[
fbInfoModel_t *m = fbInfoModelAlloc();
fbCollector_t *c = NULL;
GError *e = NULL;

fbCollectorSetSFlowTranslator(c, &e);
                 ])],[ENABLE_IPFIX=1],[ENABLE_IPFIX=0])

        if test "x${ENABLE_IPFIX}" = "x1"
        then
            AC_MSG_RESULT([yes])
            AC_CHECK_DECLS([FB_ENABLE_SCTP, HAVE_OPENSSL, HAVE_SPREAD])

            libfixbuf_have_version="${sk_pkg_modversion} >= ${libfixbuf_required_version}"
        else
            AC_MSG_RESULT([no])
            AC_MSG_NOTICE([Building without IPFIX support: pkg-config found libfixbuf-${sk_pkg_modversion} but failed to compile a program that uses it. Details in config.log.])
            if ${sk_withval_used}
            then
                AC_MSG_ERROR([unable to use libfixbuf; fix or remove --with-libfixbuf switch])
            fi
        fi

        # Restore cached values
        LDFLAGS="${sk_save_LDFLAGS}"
        LIBS="${sk_save_LIBS}"
        CFLAGS="${sk_save_CFLAGS}"
        CPPFLAGS="${sk_save_CPPFLAGS}"
    fi

    if test "x${ENABLE_IPFIX}" = "x0"
    then
        FIXBUF_LDFLAGS=
        FIXBUF_CFLAGS=
    fi

    AM_CONDITIONAL(HAVE_FIXBUF, [test "x${ENABLE_IPFIX}" = "x1"])

    AC_DEFINE_UNQUOTED([ENABLE_IPFIX],[${ENABLE_IPFIX}],
        [Define to 1 to build with support for IPFIX.  Define to 0 otherwise.
         Requires libfixbuf-1.7.0 or later support and the
         <fixbuf/public.h> header file.])

])# AX_PKG_CHECK_LIBFIXBUF

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
