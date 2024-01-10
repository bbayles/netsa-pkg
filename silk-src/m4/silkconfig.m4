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

dnl RCSIDENT("$SiLK: silkconfig.m4 b44e8c62ec61 2023-08-30 18:14:07Z mthomas $")

# ---------------------------------------------------------------------------
# SILK_AC_COMPILER
#
#    Set the compiler and compilation flags
#
AC_DEFUN([SILK_AC_COMPILER],[
    AM_PROG_CC_C_O
    AC_REQUIRE([AC_PROG_CPP])

    AC_SUBST(SK_SRC_INCLUDES)
    AC_SUBST(SK_CPPFLAGS)
    AC_SUBST(SK_CFLAGS)
    AC_SUBST(WARN_CFLAGS)
    AC_SUBST(SK_LDFLAGS)

    case "$srcdir" in
    .) SK_SRC_INCLUDES=""     ;;
    *) SK_SRC_INCLUDES='-I. ' ;;
    esac

    SK_SRC_INCLUDES=$SK_SRC_INCLUDES'-I$(srcdir) -I$(top_builddir)/src/include -I$(top_srcdir)/src/include'
    SK_CPPFLAGS='-DNDEBUG'

    # We need to have the user enable static libraries on Cygwin
    case ${build_os} in
        cygwin* | mingw* | cegcc*)
            if test "X${enable_static}" = Xno
            then
                AC_MSG_ERROR([You must specify --disable-shared or --enable-static to the configure script when building ${PACKAGE} on ${build_os}])
            fi
            ;;
    esac

    # Add platform specific flags
    case "${host_cpu}-${host_os}" in
        *-aix*)
            # The following allows 2GB address space.
            SK_LDFLAGS="$SK_LDFLAGS -Wl,-bmaxdata:0x80000000"
            # Enable thread-safe errno
            SK_CPPFLAGS="$SK_CPPFLAGS -D_THREAD_SAFE=1"
            ;;
        *solaris*)
            # Enable thread-safe errno
            SK_CPPFLAGS="$SK_CPPFLAGS -D_REENTRANT=1"
            ;;
        *-hpux*)
            # Enable thread-safe errno
            SK_CPPFLAGS="$SK_CPPFLAGS -D_THREAD_SAFE=1"
            ;;
    esac

    # DISABLE OPTIMIZATION: Remove optimization from the CFLAGS; if
    # -O2 was added by AC_PROG_CC
    sk_add_o3=1
    AC_ARG_ENABLE([optimization],
        [AS_HELP_STRING([--disable-optimization],
            [disable optimization (default is to build SiLK with -O3); use --enable-optimization=VAL to set optimization to VAL])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            # User said "--disable-optimization".  Unconditionally
            # remove -O[0-9] from the CFLAGS.
            CFLAGS=`echo " $CFLAGS " | sed 's/ -O[0-9] / /g'`
            sk_add_o3=0
        elif test "x$enableval" != "xyes"
        then
            # User passed in their own optimation flags on this switch
            CFLAGS=`echo " $CFLAGS " | sed 's/ -O[0-9] / /g'`
            CFLAGS="$CFLAGS $enableval"
            sk_add_o3=0
        fi
        ]])
    if test "x$sk_add_o3" = "x1"
    then
        # User didn't specify the switch; if the user didn't specify
        # any CFLAGS to configure (i.e., "$silk_init_cflags" is empty)
        # remove any optimization added by AC_PROG_CC and add -O3 now
        # if the compiler understands it.
        if test "x$silk_init_cflags" = "x"
        then
            sk_add_o3=""
            SILK_AC_COMP_ADDITIONAL_FLAGS(sk_add_o3, [-O3])
            if test "xsk_add_o3" != "x"
            then
                CFLAGS=`echo " $CFLAGS " | sed 's/ -O[[0-9]] / /g'`
                CFLAGS="$CFLAGS $sk_add_o3"
            fi
        fi
    fi

    # DISABLE/ENABLE DEBUGGING: Remove -g from CFLAGS unless it was
    # specified in the CFLAGS value the passed to configure.  Add it
    # if command line option is given
    sk_have_g=`echo "  $silk_init_cflags " | grep '. -g '`
    if test -z "$sk_have_g"
    then
        # Remove it
        CFLAGS=`echo " $CFLAGS " | sed 's/ -g / /g'`
    fi
    AC_ARG_ENABLE([debugging],
        [AS_HELP_STRING([--enable-debugging],
            [add compiler flags for debugging symbols [no]])[]dnl
        ],[[
        if test "x$enableval" != "xno"
        then
            # Add the switch
            CFLAGS="$CFLAGS -g"
        fi
    ]])

    # DISABLE ASSERT: Remove -DNDEBUG from SK_CPPFLAGS
    AC_ARG_ENABLE([assert],
        [AS_HELP_STRING([--enable-assert],
            [enable run-time checks with assert() [no]])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            SK_CPPFLAGS=`echo " $SK_CPPFLAGS " | sed 's/ -DNDEBUG / /'`
        fi
    ]])

    # Add additional compiler flags to SK_CFLAGS
    SILK_AC_COMP_ADDITIONAL_FLAGS([SK_CFLAGS],[-fno-strict-aliasing])

    # ENABLE GCOV (coverage testing): Add the -fprofile-arcs
    # -ftest-coverage switches to SK_CFLAGS and disable optimization
    AC_ARG_ENABLE([gcov],
        [AS_HELP_STRING([--enable-gcov],
            [add compiler flags to support gcov testing [no]])[]dnl
        ],[[
        if test "x$enableval" != "xno"
        then
            CFLAGS=`echo " $CFLAGS " | sed 's/ -O[0-9] / /g'`
            SK_CFLAGS="$SK_CFLAGS -fprofile-arcs -ftest-coverage"
        fi
    ]])

    # ENABLE GPROG (profiling): Add the -pg switch to SK_CFLAGS and
    # enable debugging symbols
    AC_ARG_ENABLE([gprof],
        [AS_HELP_STRING([--enable-gprof],
            [add compiler flags to support gprof profiling [no]])[]dnl
        ],[[
        if test "x$enableval" != "xno"
        then
            CFLAGS="$CFLAGS -g"
            SK_CFLAGS="$SK_CFLAGS -pg"
        fi
    ]])

    # ENABLE/DISABLE WARNINGS: Set the WARN_CFLAGS variable unless the
    # user says no or provides their own set of flags
    sk_add_warnings=1
    AC_ARG_ENABLE([warnings],
        [AS_HELP_STRING([--disable-warnings],
            [omit CC warning flags in the default CFLAGS. If value provided, add that to the default CFLAGS])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            sk_add_warnings=0
        elif test "x$enableval" != "xyes"
        then
            # User provide their own warning flags
            sk_add_warnings=0
            WARN_CFLAGS="$WARN_CFLAGS $enableval"
        fi
        ]])
    if test $sk_add_warnings = 1
    then
        # User didn't specify the switch; so add the warning flags
        SILK_AC_COMP_ADDITIONAL_FLAGS([WARN_CFLAGS],[-Wall -Wextra -Wmissing-prototypes -Wformat=2 -Wdeclaration-after-statement -Wpointer-arith])
    fi

    # ENABLE/DISABLE ADDITIONAL WARNINGS: Similar to previous case
    sk_enable_extra_warnings=0
    AC_ARG_ENABLE([extra-warnings],
        [AS_HELP_STRING([--enable-extra-warnings],
            [add additional warning flags to the default CFLAGS. If value provided, add that to the default CFLAGS])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            sk_enable_extra_warnings=1
        elif test "x$enableval" != "xno"
        then
            # User provide their own warning flags
            WARN_CFLAGS="$WARN_CFLAGS $enableval"
        fi
        ]])
    if test $sk_enable_extra_warnings = 1
    then
        SILK_AC_COMP_ADDITIONAL_FLAGS([WARN_CFLAGS],[-Wshadow -Wundef -Wunreachable-code -pedantic -Wno-long-long -fstrict-overflow -Wstrict-overflow=4])
        #  -Wconversion doesn't seem to understand integers smaller than
        #  uint32---that is, it warns about them when it shouldn't
        #SILK_AC_COMP_ADDITIONAL_FLAGS([WARN_CFLAGS],[-Wconversion])
    fi

    # Try to find the compiler switch that promotes warning messages
    # to errors and store that flag in '$sk_werror'.  Use this in
    # place of AC_LANG_WERROR since AC_LANG_WERROR applies to *ALL*
    # configure tests and there is no way to disable it once enabled
    # nor a way to enable it for only selected tests.
    #
    # Check for -Werror (gcc) or -errwarn (solaris cc)
    SILK_AC_COMP_ADDITIONAL_FLAGS([sk_werror],[-Werror])
    if test "X${sk_werror}" = X
    then
        SILK_AC_COMP_ADDITIONAL_FLAGS([sk_werror],[-errwarn])
    fi

    # Additional compiler characteristics
    AC_C_CONST
    AC_C_INLINE
    AC_C_VOLATILE

    # Check whether the compiler understands C99'ism __func__
    AC_MSG_CHECKING([whether the compiler understands __func__])
    sk_save_CFLAGS="${CFLAGS}"
    CFLAGS="${sk_werror} ${CFLAGS}"
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([
#include <stdio.h>
int foo(void)
{
    return printf("This is %s()\n", __func__);
}
],[
              foo();
             ])
        ],[
            AC_DEFINE([HAVE_C99___FUNC__],[1],
                [Define to 1 if your compiler understands __func__.])
            AC_MSG_RESULT([yes])],
        [AC_MSG_RESULT([no])])
    CFLAGS="${sk_save_CFLAGS}"

    # Check whether the compiler understands __attribute__((__used__))
    AC_MSG_CHECKING([whether the compiler understands __attribute__((__used__))])
    sk_save_CFLAGS="$CFLAGS"
    CFLAGS="${sk_werror} $CFLAGS"
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([],[
             static char *x __attribute__((__used__)) = "used";
             ])
        ],[
            AC_DEFINE([HAVE_COMP_ATTRIBUTE_USED],[1],
                [Define to 1 if your compiler understands __attribute__((__used__)).])
            AC_MSG_RESULT([yes])],
        [AC_MSG_RESULT([no])])
    CFLAGS="$sk_save_CFLAGS"

    # Check whether the compiler allows
    # __attribute__((format(printf,...))) to apply to printf-style
    # function-pointer typedefs
    AC_MSG_CHECKING([whether __attribute__((format(printf,...))) may apply to typedefs])
    sk_save_CFLAGS="$CFLAGS"
    CFLAGS="${sk_werror} $CFLAGS"
    AC_COMPILE_IFELSE(
        [AC_LANG_PROGRAM([
             typedef int (*printf_like_func)(const char *fmt, ...)
                 __attribute__((format (printf, 1, 2)));
             ],[])
        ],[
            AC_DEFINE([HAVE_COMP_ATTRIBUTE_PRINTF_TYPEDEF],[1],
                [Define to 1 if your compiler allows __attribute__((format(printf, ...))) to be applied to printf-style function-pointer typedefs.])
            AC_MSG_RESULT([yes])],
        [AC_MSG_RESULT([no])])
    CFLAGS="$sk_save_CFLAGS"

    # Get the filename extension to use for SiLK plug-ins
    if test "x$shrext_cmds" = "x"
    then
        PLUGIN_SUFFIX=.so
    else
        sk_save_module="$module"
        module=yes
        eval PLUGIN_SUFFIX="$shrext_cmds"
        module="$sk_save_module"
        if test "x$module" = "x"
        then
            module=yes
            eval PLUGIN_SUFFIX="$shrext_cmds"
            unset module
        else
            sk_module_save="$module"
            module=yes
            eval PLUGIN_SUFFIX="$shrext_cmds"
            module="$sk_module_save"
        fi
    fi
    AC_DEFINE_UNQUOTED([PLUGIN_SUFFIX], ["$PLUGIN_SUFFIX"],
        [Filename extension to use for SiLK plug-ins])

    # libtool flags to use when building a SiLK plugin.  We should be
    # able to include "-module" in this list, but automake complains
    # when the <plugin-name>_LDFLAGS variables in the Makefile.am
    # files appear to be empty, so we set that variable to "-module
    # $(SILK_PLUGIN_LIBTOOL_FLAGS)"
    AC_SUBST([SILK_PLUGIN_LIBTOOL_FLAGS],
             ["-avoid-version -shrext $PLUGIN_SUFFIX"])

    # Byte order.  Do not define the CPP macros BIG_ENDIAN and
    # LITTLE_ENDIAN until after all tests have run to avoid
    # conflicting with any definitions in the system headers.
    AC_C_BIGENDIAN()
    AC_EGREP_CPP([big endian],[
#if defined(WORDS_BIGENDIAN) && WORDS_BIGENDIAN == 1
big endian
#else
little endian
#endif
        ], [BIG_ENDIAN=1 ; LITTLE_ENDIAN=0],
        [BIG_ENDIAN=0 ; LITTLE_ENDIAN=1])

    # Removed the following in favor of an actual architecture test.
    # This is because some platforms may allow unaligned access, but
    # have it be slower than the corresponsing memcpy, since it is
    # actually implemented in software rather than hardware.  Instead,
    # check for the hardware that we know supports fast unaligned
    # access.
    #
    # AX_CHECK_ALIGNED_ACCESS_REQUIRED
    case $host in
        i?86-*|x86_64-*|amd64-*|powerpc-*|powerpc64-*) ;;
        *) AC_DEFINE([HAVE_ALIGNED_ACCESS_REQUIRED], [1],
                [Define if pointers to integers require aligned access]) ;;
    esac

])#SILK_AC_COMPILER


# ---------------------------------------------------------------------------
# SILK_AC_COMP_ADDITIONAL_FLAGS(var, flag_list)
#
#    For each flag listed in FLAG_LIST, add it to the specified VAR if
#    the compiler understands it.
#
AC_DEFUN([SILK_AC_COMP_ADDITIONAL_FLAGS],[
    AC_LANG_CONFTEST([AC_LANG_SOURCE([[
        int main(int argc, char **argv) { int x = 0; if (argv[argc-1]) { ++x; } return x; } ]])])

    for sk_cc_flag in $2
    do
        AC_MSG_CHECKING([whether ${CC-cc} understands $sk_cc_flag])
        sk_cc_cmd="${CC-cc} $sk_cc_flag -c conftest.c"
        sk_cc_out="`$sk_cc_cmd 2>&1`"
        if test "X$sk_cc_out" = X
        then
            $1="$$1 $sk_cc_flag"
            AC_MSG_RESULT([yes])
        else
            AC_MSG_RESULT([no])
            echo "$as_me:$LINENO: failed command was" >&5
            echo "$as_me:$LINENO: $sk_cc_cmd" >&5
            echo "$as_me:$LINENO: $sk_cc_out" >&5
        fi
    done
])#SILK_AC_COMP_ADDITIONAL_FLAGS


# ---------------------------------------------------------------------------
# SILK_AC_COMP_INCLUDE_TO_CFLAG
#
#    Some defines really need to be set before any header files are
#    read, but this creates a problem for C files generated by YACC
#    and LEX.
#
#    So, for defines that the system headers use, grep their values
#    out of the confdefs.h file and add them to CPPFLAGS.
#
AC_DEFUN([SILK_AC_COMP_INCLUDE_TO_CFLAG],[
    for sk_defined in _ALL_SOURCE _GNU_SOURCE _FILE_OFFSET_BITS _LARGEFILE_SOURCE _LARGE_FILES
    do
        sk_def_test=`echo $sk_defined | sed -e 's/,.*$//'`
        sk_def_flag=`echo $sk_defined | sed -e 's/^.*,//'`

        val=`awk '/^# *define[ \t]+'$sk_def_test'[ \t]/ { print $NF; exit; }' confdefs.h`
        if test "X$val" != X
        then
            SK_CPPFLAGS="$SK_CPPFLAGS -D$sk_def_flag=$val"
        fi
    done
])# SILK_AC_COMP_INCLUDE_TO_CFLAG


# ---------------------------------------------------------------------------
# SILK_AC_COMP_SHARED_OBJECT
#
#    Set variables for building shared objects (dynamic libraries)
#
AC_DEFUN([SILK_AC_COMP_SHARED_OBJECT],[
    AC_SUBST(SHLIB_EXT)
    AC_SUBST(SHLIB_LD)
    AC_SUBST(SHLIB_LDFLAGS)
    AC_SUBST(SHLIB_LIBS)
    AC_SUBST(SHLIB_CCFLAGS)
    AC_SUBST(USES_DLOPEN_FLAGS)

    AC_MSG_NOTICE([(${PACKAGE}) Determining settings for shared object support])

    AC_MSG_CHECKING([standard extension (SHLIB_EXT)])
    if test -z "$SHLIB_EXT"
    then
        SHLIB_EXT=so
        #case $build_os in
        #esac
    fi
    AC_MSG_RESULT($SHLIB_EXT)


    AC_MSG_CHECKING([for compile-time flags (SHLIB_CCFLAGS)])
    if test -z "$SHLIB_CCFLAGS"
    then
        SHLIB_CCFLAGS="-DPIC -fPIC"
        case $build_os in
            aix*)       SHLIB_CCFLAGS="" ;;
            osf*)       SHLIB_CCFLAGS="" ;;
        esac
    fi
    if test -n "$SHLIB_CCFLAGS"
    then
        AC_MSG_RESULT($SHLIB_CCFLAGS)
    else
        AC_MSG_RESULT([(none required)])
    fi


    AC_MSG_CHECKING([for link command (SHLIB_LD)])
    if test -z "$SHLIB_LD"
    then
        # Use CC normally, but use LD on some platforms
        SHLIB_LD='$(CC)'
        case $build_os in
            aix*)       SHLIB_LD='$(LD)' ;;
            osf*)       SHLIB_LD='$(LD)' ;;
        esac
    fi
    AC_MSG_RESULT($SHLIB_LD)


    AC_MSG_CHECKING([the link-time flags (SHLIB_LDFLAGS)])
    if test -z "$SHLIB_LDFLAGS"
    then
        SHLIB_LDFLAGS='$(SHLIB_CCFLAGS) -shared'
        case $build_os in
            aix*)       SHLIB_LDFLAGS="-G -bnoentry -bexpall -b32 -bM:SRE -bmaxdata:0x80000000" ;;
            darwin*)    SHLIB_LDFLAGS="-bundle -flat_namespace -undefined suppress" ;;
            osf*)       SHLIB_LDFLAGS="-shared -expect_unresolved '*'" ;;
            solaris*)   SHLIB_LDFLAGS="$SHLIB_LDFLAGS -mimpure-text" ;;
        esac
    fi
    if test -n "$SHLIB_LDFLAGS"
    then
        AC_MSG_RESULT($SHLIB_LDFLAGS)
    else
        AC_MSG_RESULT([(none required)])
    fi


    AC_MSG_CHECKING([for extra libraries (SHLIB_LIBS)])
    if test -z "$SHLIB_LIBS"
    then
        SHLIB_LIBS=
        case $build_os in
            aix*)       SHLIB_LIBS="-lc -ldl" ;;
        esac
    fi
    if test -n "$SHLIB_LIBS"
    then
        AC_MSG_RESULT($SHLIB_LIBS)
    else
        AC_MSG_RESULT([(none required)])
    fi


    AC_MSG_CHECKING([for flags to export symbols (USES_DLOPEN_FLAGS)])
    if test -z "$USES_DLOPEN_FLAGS"
    then
        USES_DLOPEN_FLAGS=""
        case $build_os in
            # The "100" on the next line is arbitrarily large.  We
            # don't want to have the linker doing gc on unreferenced
            # functions, since they may be referenced by run-time
            # dynamically-loaded libraries
            aix*)       USES_DLOPEN_FLAGS="-Wl,-brtl,-bexpall,-bgcbypass:100" ;;
            linux*)     USES_DLOPEN_FLAGS="-rdynamic" ;;
            openbsd*)   USES_DLOPEN_FLAGS="-Wl,-export-dynamic" ;;
        esac
    fi
    if test -n "$USES_DLOPEN_FLAGS"
    then
        AC_MSG_RESULT($USES_DLOPEN_FLAGS)
    else
        AC_MSG_RESULT([(none required)])
    fi

    AC_MSG_NOTICE([(${PACKAGE}) Shared object checks completed])
])#SILK_AC_COMP_SHARED_OBJECT


# ---------------------------------------------------------------------------
# SILK_AC_FINALIZE
#
#    Set any variables and create any final defintions before creating
#    the headers, makefiles, etc.
#
AC_DEFUN([SILK_AC_FINALIZE],[
    # Add libraries to the default list
    LIBS=`echo "${SNAPPY_LDFLAGS} ${LZO_LDFLAGS} ${ZLIB_LDFLAGS} ${LIBS}" | sed 's/   */ /g'`

    # Add include flags
    SK_CPPFLAGS=`echo "${SK_CPPFLAGS} ${ZLIB_CFLAGS} ${LZO_CFLAGS} ${SNAPPY_CFLAGS} ${PCAP_CFLAGS}" | sed 's/   */ /g'`

    # Define these after all tests have run; some system headers also
    # define these macros
    AC_DEFINE_UNQUOTED([BIG_ENDIAN], [${BIG_ENDIAN}],
        [Define to 1 if your processor stores words with the most
         significant byte first (like Motorola and SPARC, unlike Intel).
         Define to 0 otherwise.  See also SK_LITTLE_ENDIAN.])
    AC_DEFINE_UNQUOTED([LITTLE_ENDIAN], [${LITTLE_ENDIAN}],
        [Define to 1 if your processor stores words with the least
         significant byte first (like Intel, unlike Motorola and SPARC).
         Define to 0 otherwise.  See also SK_BIG_ENDIAN.])

])#SILK_AC_FINALIZE


# ---------------------------------------------------------------------------
# SILK_AC_FIND_SITE_MAKEFILES
#
#    Find all the subdirectories to build.
#
#    Output variables: SILK_SITE_SUBDIRS
#
AC_DEFUN([SILK_AC_FIND_SITE_MAKEFILES],[
    AC_SUBST(SILK_SITE_SUBDIRS)

    # build the list of sites by a glob pattern
    m4_define([sk_site_list],
              [m4_bpatsubst(m4_esyscmd([echo site/[A-Za-z]*/Makefile.am]),
                            [Makefile\.am], [Makefile])])

    AC_CONFIG_FILES(sk_site_list)

    # create directory list
    for skdir in sk_site_list
    do
        skdir=`echo "$skdir" | sed 's,^site/\(.*\)/Makefile$,\1,'`
        SILK_SITE_SUBDIRS="$SILK_SITE_SUBDIRS $skdir"
    done
])


# ---------------------------------------------------------------------------
# SILK_AC_INIT - initialize SiLK autoconf magic
#
#    All configure.in files should start with an invocation of
#    SILK_AC_INIT
#
AC_DEFUN([SILK_AC_INIT],[
    SPLINT_FLAGS="+posixlib +unixlib -weak"
    AC_SUBST(SPLINT_FLAGS)
    AC_SUBST(SILK_VERSION_INTEGER)

    PACKING_LOGIC_PATH_DEFAULT="site/twoway/packlogic-twoway.c"
    SILK_DATA_ROOTDIR_DEFAULT=/data

    # Set a version number as an integer.  Note: embedded [] are to
    # prevent m4 from treating $1... as arguments to this function.
    SILK_VERSION_INTEGER=`echo "$PACKAGE_VERSION" | sed 's/-.*//' | awk -F. '{print ($[]1 * 1000000 + $[]2 * 1000 + $[]3)}'`
    AC_DEFINE_UNQUOTED([VERSION_INTEGER], [$SILK_VERSION_INTEGER],
        [Set to an integer describing this version of SiLK.])

    # Stash the current CFLAGS value
    silk_init_cflags="$CFLAGS"

    # Groups of Makefile.in's to create
    silk_enable_analysis_tools=1
    silk_enable_packing_tools=1

    # Tests to run
    silk_enable_extra_checks=0

    # append locations in install directory to PKG_CONFIG_PATH
    silk_extra_pkg_config=`eval "test \"x${prefix}\" = xNONE && prefix=\"${ac_default_prefix}\" ; test \"x${exec_prefix}\" = xNONE && exec_prefix=\"\\\${prefix}\" ; echo \"${libdir}/pkgconfig:${datarootdir}/pkgconfig\" "`
    if test "x$PKG_CONFIG_PATH" = "x"
    then
        PKG_CONFIG_PATH="$silk_extra_pkg_config"
    else
        PKG_CONFIG_PATH="$PKG_CONFIG_PATH:$silk_extra_pkg_config"
    fi
    export PKG_CONFIG_PATH


])# SILK_AC_INIT


# ---------------------------------------------------------------------------
# SILK_AC_ARG_DATA_ROOTDIR
#
#    Let the user specify the base directory where the packed data
#    should be stored and from where it will be read.
#
#    Output variable: SILK_DATA_ROOTDIR
#
AC_DEFUN([SILK_AC_ARG_DATA_ROOTDIR],[
    AC_SUBST(SILK_DATA_ROOTDIR)

    AC_ARG_ENABLE([data-rootdir],
        [AS_HELP_STRING([--enable-data-rootdir=DIR],
            [default location of packed data files [/data]])[]dnl
        ],[[
        if test "x$enableval" != "xyes"
        then
            SILK_DATA_ROOTDIR="$enableval"
        fi
        ]])

    if test "x${SILK_DATA_ROOTDIR}" = "x"
    then
        SILK_DATA_ROOTDIR="${SILK_DATA_ROOTDIR_DEFAULT}"
    fi
])# SILK_AC_ARG_DATA_ROOTDIR


# ---------------------------------------------------------------------------
# SILK_AC_ARG_DISABLE_ANALYSIS_TOOLS
#
#    Do not build the analysis tools
#
#    Output make condition variable: BUILD_ANALYSIS_TOOLS
#
AC_DEFUN([SILK_AC_ARG_DISABLE_ANALYSIS_TOOLS],[
    AC_ARG_ENABLE([analysis-tools],
        [AS_HELP_STRING([--disable-analysis-tools],
            [do not descend into the analysis tools directories when building the software])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            silk_enable_analysis_tools=0
        fi]])

    AM_CONDITIONAL(BUILD_ANALYSIS_TOOLS,
        [test "x$silk_enable_analysis_tools" = "x1"])
]) # SILK_AC_ARG_DISABLE_ANALYSIS_TOOLS


# ---------------------------------------------------------------------------
# SILK_AC_ARG_DISABLE_PACKING_TOOLS
#
#    Do not build the packing tools
#
#    Output make condition variable: BUILD_PACKING_TOOLS
#
AC_DEFUN([SILK_AC_ARG_DISABLE_PACKING_TOOLS],[
    AC_ARG_ENABLE([packing-tools],
        [AS_HELP_STRING([--disable-packing-tools],
            [do not descend into the packing tools directories when building the software])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            silk_enable_packing_tools=0
        fi]])

    AM_CONDITIONAL(BUILD_PACKING_TOOLS,
        [test "x$silk_enable_packing_tools" = "x1"])
]) # SILK_AC_ARG_DISABLE_PACKING_TOOLS


# ---------------------------------------------------------------------------
# SILK_AC_ARG_DISABLE_SPLIT_WEB
#
#    Do not pack the web flows separately
#
AC_DEFUN([SILK_AC_ARG_DISABLE_SPLIT_WEB],[
    AC_ARG_ENABLE([web-split],
        [AS_HELP_STRING([--disable-web-split],
            [in the packer, do not pack the web flows separately from other flows])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            silk_enable_web_split=0
        fi]])
]) # SILK_AC_ARG_DISABLE_SPLIT_WEB




# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_EXTRA_CHECKS
#
#    During "make check", run some tests where the results are
#    inconsistent.  Most of these tests involve floating point
#    arithmetic, which can differ depending on the processor,
#    compiler, and optimization level.
#
#    Output make condition variable: RUN_EXTRA_CHECKS
#
AC_DEFUN([SILK_AC_ARG_ENABLE_EXTRA_CHECKS],[
    AC_ARG_ENABLE([extra-checks],
        [AS_HELP_STRING([--enable-extra-checks],
            [run additional tests during "make check" that are known to fail on some architectures and/or compilers [no]])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            silk_enable_extra_checks=1
        fi]])

    AM_CONDITIONAL(RUN_EXTRA_CHECKS,[test "x$silk_enable_extra_checks" = "x1"])
])# SILK_AC_ARG_ENABLE_EXTRA_CHECKS






# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_IPSET_COMPATIBILITY
#
#    Select the release of SiLK that the default output from the IPset
#    tools is compatible with.
#
#    An argument of 3.14.0 or later makes the default IPset version 5
#    for IPv6 IPsets and 4 for IPv4 IPsets.
#
#    An argument of 3.7.0 or later makes the default IPset version 4
#    for both IPv6 and IPv4 IPsets.
#
#    Any other argument causes IPset files to be fully backwards
#    compatible, as does not specifying the argument or specifying an
#    invalid argument.
#
#    Output variable: IPSET_DEFAULT_VERSION
#
AC_DEFUN([SILK_AC_ARG_ENABLE_IPSET_COMPATIBILITY],[
    SK_IPSET_COMPATIBILITY=1.0.0
    SK_IPSET_DEFAULT_VERSION=2

    AC_ARG_ENABLE([ipset-compatibility],
        [AS_HELP_STRING([--enable-ipset-compatibility],
            [select release of SiLK that the default output from IPset tools is compatible with (changes at 3.7.0, 3.14.0) [1.0.0]])[]dnl
        ],[],[
            enableval="yes"
        ])

    if test "x${enableval}" = "xno" || test "x${enableval}" = "xyes"
    then
        :
    else
        # Double the square brackets since m4 removes outer set
        sk_expr=`expr "X${enableval}" : 'X[[0-9]][[0-9.]]*$'`
        if test "${sk_expr}" -gt 0
        then
            # Use $[]1 so $\1 is not taken as argument to m4 function
            SK_IPSET_COMPATIBILITY=`echo "0.${enableval}" | awk -F. '{a = $[]2 % 1000; b = $[]3 % 1000; c = $[]4 % 1000; vers = a * 1000000 + b * 1000 + c; if (vers >= 3014000) { print "3.14.0"; } else if (vers >= 3007000) { print "3.7.0"; } else { print "1.0.0"; } }'`
            AC_MSG_NOTICE([(${PACKAGE}) Setting default IPset compatibility to SiLK-${SK_IPSET_COMPATIBILITY} (SiLK-${enableval} requested)])
        else
            AC_MSG_WARN([[(${PACKAGE}) Unable to parse --enable-ipset-compatibilty argument '${enableval}' as a version number]])
        fi
    fi

    if test "x${SK_IPSET_COMPATIBILITY}" = "x3.14.0"
    then
        SK_IPSET_DEFAULT_VERSION=5
    elif test "x${SK_IPSET_COMPATIBILITY}" = "x3.7.0"
    then
        SK_IPSET_DEFAULT_VERSION=4
    elif test "x${SK_IPSET_COMPATIBILITY}" != "x1.0.0"
    then
        SK_IPSET_COMPATIBILITY=1.0.0
    fi

    AC_DEFINE_UNQUOTED([IPSET_DEFAULT_VERSION], [${SK_IPSET_DEFAULT_VERSION}],
        [Set to the default IPset record version to use when writing to disk.])
])# SILK_AC_ARG_ENABLE_IPSET_COMPATIBILITY


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_IPV6
#
#    Enable support for IPv6 addresses in SiLK Flow records.
#    Default: no
#
#    Output variable: ENABLE_IPV6
#
AC_DEFUN([SILK_AC_ARG_ENABLE_IPV6],[
    ENABLE_IPV6=0

    AC_ARG_ENABLE([ipv6],
        [AS_HELP_STRING([--enable-ipv6],
            [enable support for capturing, storing, and querying flow records containing IPv6 addresses [no]])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            ENABLE_IPV6=1
        fi]])

    AC_DEFINE_UNQUOTED([ENABLE_IPV6], [$ENABLE_IPV6],
        [Define to 1 to build with support for capturing, storing, and querying flow records containing IPV6 addresses.])
    AM_CONDITIONAL(SK_ENABLE_IPV6, [test "x$ENABLE_IPV6" = x1])
])# SILK_AC_ARG_ENABLE_IPV6


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_INET6_NETWORKING
#
#    Enable support for listening-on/connecting-to IPv6 network
#    addresses.  Default: yes if getaddrinfo is found.
#
#    Output variable: ENABLE_INET6_NETWORKING
#
AC_DEFUN([SILK_AC_ARG_ENABLE_INET6_NETWORKING],[
    ENABLE_INET6_NETWORKING=0
    if test "x$ac_cv_func_getaddrinfo" = "xyes"
    then
        ENABLE_INET6_NETWORKING=1
    fi

    AC_ARG_ENABLE([inet6-networking],
        [AS_HELP_STRING([--disable-inet6-networking],
            [omit support for listening-on/connecting-to IPv6 network sockets [auto]])[]dnl
        ],[[
        if test "x$enableval" = "xno"
        then
            ENABLE_INET6_NETWORKING=0
        fi]])

    AC_DEFINE_UNQUOTED([ENABLE_INET6_NETWORKING], [$ENABLE_INET6_NETWORKING],
        [Define to 1 to build with listening-on/connecting-to IPv6 network sockets.  Requires getaddrinfo() function.])
])# SILK_AC_ARG_ENABLE_INET6_NETWORKING


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_LOCALTIME
#
#    Use the local timezone for command inputs and printing records
#
AC_DEFUN([SILK_AC_ARG_ENABLE_LOCALTIME],[
    ENABLE_LOCALTIME=0

    AC_ARG_ENABLE([localtime],
        [AS_HELP_STRING([--enable-localtime],
            [use the local timezone for command inputs and for printing records.  Default is to use UTC.  (Files are always stored by UTC time.)])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            ENABLE_LOCALTIME=1
        fi]])

    AC_DEFINE_UNQUOTED([ENABLE_LOCALTIME], [$ENABLE_LOCALTIME],
        [Define to 1 to use the local timezone for command input and
         printing records.  Define to 0 to use UTC.])
])# SILK_AC_ARG_ENABLE_LOCALTIME




# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_OUTPUT_COMPRESSION
#
#    Set the default compression method to use for binary output files.
#
#    Output variables: ENABLE_OUTPUT_COMPRESSION
#
AC_DEFUN([SILK_AC_ARG_ENABLE_OUTPUT_COMPRESSION],[
    # The default compression method
    sk_output_comp=none

    AC_ARG_ENABLE([output-compression],
        [AS_HELP_STRING([--enable-output-compression],
            [enable or set the default compression method for binary SiLK output files. Choices (subject to library availability): none, zlib, lzo1x, snappy. [none]])[]dnl
        ],[[sk_output_comp="$enableval"]])

    case "$sk_output_comp" in
        yes)
            # use the best we can find
            sk_output_comp=none
            if test "x$ENABLE_ZLIB" = "x1"
            then
                sk_output_comp=zlib
            fi
            if test "x$ENABLE_SNAPPY" = "x1"
            then
                sk_output_comp=snappy
            fi
            if test "x$ENABLE_LZO" = "x1"
            then
                sk_output_comp=lzo1x
            fi
            ;;
        no|none)
            sk_output_comp=none
            ;;
        zlib)
            if test "x$ENABLE_ZLIB" != "x1"
            then
                AC_MSG_ERROR([output-compression=$sk_output_comp is not available because zlib was not found])
            fi
            ;;
        lzo1x)
            if test "x$ENABLE_LZO" != "x1"
            then
                AC_MSG_ERROR([output-compression=$sk_output_comp is not available because LZO was not found])
            fi
            ;;
        snappy)
            if test "x$ENABLE_SNAPPY" != "x1"
            then
                AC_MSG_ERROR([output-compression=$sk_output_comp is not available because snappy was not found])
            fi
            ;;
        *)
            AC_MSG_ERROR([output-compression=$sk_output_comp is not valid])
            ;;
    esac

    # Be certain to keep this list up-to-date with the C code in
    # silk_files.h and sksite.[ch]
    ENABLE_OUTPUT_COMPRESSION='SK_COMPMETHOD_'`echo $sk_output_comp | tr '[[a-z]]' '[[A-Z]]'`
    AC_MSG_NOTICE([(${PACKAGE}) Default output compression is $sk_output_comp])

    AC_DEFINE_UNQUOTED([ENABLE_OUTPUT_COMPRESSION],
        [$ENABLE_OUTPUT_COMPRESSION],
        [Define to the compression method to use by default for binary SiLK
         output files (see silk_files.h for valid methods).])
])# SILK_AC_ARG_ENABLE_OUTPUT_COMPRESSION


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_PACKING_LOGIC
#
#   Allow the use of a static C file to determine the packing logic
#
#   Output variables: PACKING_LOGIC_PATH
#   Defines: SK_PACKING_LOGIC_PATH
#
AC_DEFUN([SILK_AC_ARG_ENABLE_PACKING_LOGIC],[
    AC_SUBST(PACKING_LOGIC_PATH)

    sk_pack_path=

    AC_ARG_ENABLE([packing-logic],
        AS_HELP_STRING([--enable-packing-logic=PATH],
            [configure the packer (rwflowpack) to statically include PATH for the packing logic. PATH can be a complete path, relative to current directory, or relative to the configure script. When not provided, rwflowpack uses a run-time plug-in to determine the packing logic]),
        [
            if test "x$enableval" != "xno"
            then
                sk_pack_path="$enableval"
            fi
        ])

    # Cannot do plug-ins if the user has disabled shared libraries
    if test "x$sk_pack_path" = "x"
    then
        if test "x$enable_shared" = xno || test "x$STATIC_APPLICATIONS" != "x"
        then
            sk_pack_path="${PACKING_LOGIC_PATH_DEFAULT}"
            AC_MSG_NOTICE([(${PACKAGE}) Using static packing logic because of static linking])
        fi
    fi

    if test "x$sk_pack_path" != "x"
    then
        # If the path is complete, ensure the file exists.  If the
        # path is relative, check whether it exist relaltive to the
        # current directory.  If not and we are building outside the
        # source tree, check relative to ${srcdir}.
        if expr "x$sk_pack_path" : "x/" >/dev/null
        then
            # complete path
            PACKING_LOGIC_PATH="$sk_pack_path"
            AC_CHECK_FILE([$PACKING_LOGIC_PATH], ,
                AC_MSG_ERROR([Cannot find site packing logic file $PACKING_LOGIC_PATH]))
        else
            # relative path, first look relative to pwd
            PACKING_LOGIC_PATH="`pwd`/$sk_pack_path"
            AC_CHECK_FILE([$PACKING_LOGIC_PATH], , [
                case "$srcdir" in
                  .)
                    # pwd and srcdir are the time
                    AC_MSG_ERROR([Cannot find site packing logic file $sk_pack_path])
                    ;;
                  *)
                    # look relative to srcdir
                    sk_srcdir=`( cd "$srcdir" 2>/dev/null && pwd )`
                    PACKING_LOGIC_PATH="$sk_srcdir/$sk_pack_path"
                    AC_CHECK_FILE([$PACKING_LOGIC_PATH], ,
                        AC_MSG_ERROR([Cannot find site packing logic file $sk_pack_path]))
                    ;;
                esac
                ])
        fi

        AC_DEFINE_UNQUOTED([PACKING_LOGIC_PATH], "$PACKING_LOGIC_PATH",
            [Define to the path of the C source file that rwflowpack
             will use for categorizing flow records.  When this is
             undefined, rwflowpack will use a plug-in loaded at
             run-time to determine the categories.])

    fi

    AM_CONDITIONAL(HAVE_PACKING_LOGIC, [test "x$sk_pack_path" != "x"])
])# SILK_AC_ARG_ENABLE_PACKING_LOGIC


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_SPLIT_ICMP
#
#    Do not pack the web flows separately
#
AC_DEFUN([SILK_AC_ARG_ENABLE_SPLIT_ICMP],[
    AC_ARG_ENABLE([icmp-split],
        [AS_HELP_STRING([--enable-icmp-split],
            [in the packer, pack ICMP flow records separately from other flows])[]dnl
        ],[[
        if test "x$enableval" != "xno"
        then
            silk_enable_icmp_split=1
        fi]])
]) # SILK_AC_ARG_ENABLE_SPLIT_ICMP


# ---------------------------------------------------------------------------
# SILK_AC_ARG_ENABLE_STATIC_APPLICATIONS
#
#    Build all applications with static linking.
#
#    Output variables: STATIC_APPLICATIONS
#
AC_DEFUN([SILK_AC_ARG_ENABLE_STATIC_APPLICATIONS],[
    AC_SUBST(STATIC_APPLICATIONS)
    AC_ARG_ENABLE([static-applications],
        [AS_HELP_STRING([--enable-static-applications],
            [use only static libraries when linking applications [no]])[]dnl
        ],[[
        if test "x$enableval" != "xno"
        then
            STATIC_APPLICATIONS=-static
        fi]])

    AM_CONDITIONAL(HAVE_STATIC_APPLICATIONS, [test "x$STATIC_APPLICATIONS" != "x"])
]) # SILK_AC_ARG_ENABLE_STATIC_APPLICATIONS






# ---------------------------------------------------------------------------
# SILK_AC_ARG_WITH_PYTHON
#
#    Set up python environment.
#
AC_DEFUN([SILK_AC_ARG_WITH_PYTHON],[

    # Variables required when building with Python
    AC_SUBST(PYTHON_CPPFLAGS)
    AC_SUBST(PYTHON_LDFLAGS)
    AC_SUBST(PYTHON_LDFLAGS_EMBEDDED)
    AC_SUBST(PYTHON_SO_EXTENSION)

    # Variables containing Python install locations
    AC_SUBST(PYTHON_SITE_PKG)
    AC_SUBST(PYTHON_DEFAULT_SITE_PKG)

    # Variables to be compatible with AM_PATH_PYTHON()
    AC_SUBST([pythondir], [\${PYTHON_SITE_PKG}])
    AC_SUBST([pkgpythondir], [\${pythondir}/${PACKAGE}])

    # Name of the script we use to get information from Python,
    # relative to srcdir.  Export it for "make dist" purposes.
    AC_SUBST([PYTHON_INFO_PROG], [autoconf/silk-python-info.py])

    # Version of python
    AC_SUBST([PYTHON_VERSION])

    # Path to our python information script
    python_info="${srcdir}/${PYTHON_INFO_PROG}"

    # Possible names for the python interpreter
    python_names="python python3 python2 no"

    AC_ARG_VAR([PYTHON], [The Python interpreter to use for PySiLK support when no interpreter is specified to --with-python; must be Python 2.4 or later.])

    python_declined=no
    AC_ARG_WITH([python],
        [AS_HELP_STRING([[--with-python[=PYTHON]]],
            [add PySiLK "SiLK in Python" support.  If an argument is provided, it is the path to the Python interpreter to use [no]])[]dnl
        ],[
        if test "x${withval}" = "xno"
        then
            ENABLE_PYTHON=0
            python_declined=yes
        elif test "x${withval}" = "xyes"
        then
            ENABLE_PYTHON=1
        else
            # Treat the argument as the python interpreter
            PYTHON="${withval}"
            ENABLE_PYTHON=1
        fi],
        [ENABLE_PYTHON=0])

    AC_ARG_WITH([python-prefix],
        [AS_HELP_STRING([[--with-python-prefix[=DIR]]],
            [install Python modules under this prefix instead of in the Python site directory (e.g., PySiLK location will be DIR/lib/python*/silk/).  An empty argument means to use the value of PREFIX])[]dnl
        ],[
        if test "x${withval}" = "xyes"
        then
            sk_PYTHONPREFIX='${prefix}'
        elif test "x${withval}" != "xno"
        then
            sk_PYTHONPREFIX="${withval}"
        fi
        ])

    AC_ARG_WITH([python-site-dir],
        [AS_HELP_STRING([--with-python-site-dir=DIR],
            [install the files for the PySiLK module in DIR/silk/* instead of in the Python site directory])[]dnl
        ],[
        if test "x${withval}" = "xyes"
        then
            AC_MSG_ERROR([--with-python-site-dir requires an argument])
        elif test "x${withval}" != "xno"
        then
            if test "x${sk_PYTHONPREFIX}" != "x"
            then
                AC_MSG_ERROR([--with-python-site-dir cannot be used with --with-python-prefix])
            fi
            sk_PYTHONSITEDIR="${withval}"
        fi
        ])

    if test "x${python_declined}" = "xyes"
    then
        AC_MSG_NOTICE([(${PACKAGE}) Building without PySiLK support at user request])
        ENABLE_PYTHON=0
    elif test "x${ENABLE_PYTHON}" != "x1"
    then
        AC_MSG_NOTICE([(${PACKAGE}) Building without PySiLK support: --with-python not specified])
        ENABLE_PYTHON=0
    else
        # Cannot build PySiLK when not building shared libraries
        if test "x${enable_shared}" = xno || test "x${STATIC_APPLICATIONS}" != "x"
        then
            AC_MSG_NOTICE([(${PACKAGE}) Will not build PySiLK since static linking was requested])
            ENABLE_PYTHON=0
        else
            AC_MSG_NOTICE([(${PACKAGE}) Determining Python settings for PySiLK support])
        fi
    fi

    if test "x${PYTHON}" != "x"
    then
        # User specified the location of python; get full path to it
        AC_PATH_PROG([PYTHON], [${PYTHON}], [${PYTHON}])

        if test -f "${PYTHON}" && test -x "${PYTHON}"
        then
            :
        else
            AC_MSG_ERROR([(${PACKAGE}) Specified Python program '${PYTHON}' is not an executable file])
        fi

        # Get version of python, which also ensures >= Python 2.4.
        AC_MSG_CHECKING([version of ${PYTHON}])

        echo "${as_me}:${LINENO}: python_info_result=\`\"${PYTHON}\" \"${python_info}\" --print-version\`" >&AS_MESSAGE_LOG_FD
        python_info_result=`"${PYTHON}" "${python_info}" --print-version 2>&AS_MESSAGE_LOG_FD`
        python_status=$?
        echo "${as_me}:${LINENO}: \${python_info_result} = ${python_info_result}" >&AS_MESSAGE_LOG_FD
        echo "${as_me}:${LINENO}: \$? = ${python_status}" >&AS_MESSAGE_LOG_FD

        if test ${python_status} -eq 0
        then
            PYTHON_VERSION="${python_info_result}"
            AC_MSG_RESULT([${PYTHON_VERSION}])
        else
            if test "x${python_info_result}" != x
            then
                AC_MSG_RESULT([${python_info_result}])
            else
                AC_MSG_RESULT([unknown])
            fi
            if test "x${ENABLE_PYTHON}" = "x1"
            then
                AC_MSG_ERROR([(${PACKAGE}) PySiLK cannot use the Python program '${PYTHON}'])
            fi
        fi

        # Get the basename of python and warn if it ends with 'python'
        py_basename=`echo "x${PYTHON}" | sed 's%.*/%%'`
        if test "x${py_basename}" = xpython
        then
            AC_MSG_WARN([using 'python3' or 'python2' explicitly is recommended over 'python'])
        fi

    else
        # Find a python interpreter since none was specified.  We
        # always want to do this since we need to support stand-alone
        # python scripts in addition to PySiLK.  Take the first one we
        # find.

        # It is tempting to use AC_PATH_PROGS_FEATURE_CHECK() to loop
        # over ${python_names} here, but that chooses the first of any
        # of the candidates it finds on PATH

        AC_MSG_CHECKING([for a suitable python])
        for maybe_python in ${python_names}
        do
            if test ${maybe_python} = no
            then
                break
            fi
            python_status=1

            AC_PATH_PROGS_FEATURE_CHECK([PYTHON], [${maybe_python}], [

                echo "${as_me}:${LINENO}: python_info_result=\`\"${ac_path_PYTHON}\" \"${python_info}\" --print-version\`" >&AS_MESSAGE_LOG_FD
                python_info_result=`"${ac_path_PYTHON}" "${python_info}" --print-version 2>&AS_MESSAGE_LOG_FD`
                python_status=$?
                echo "${as_me}:${LINENO}: \${python_info_result} = ${python_info_result}" >&AS_MESSAGE_LOG_FD
                echo "${as_me}:${LINENO}: \$? = ${python_status}" >&AS_MESSAGE_LOG_FD

                if test ${python_status} -eq 0
                then
                    ac_cv_path_PYTHON="${ac_path_PYTHON}"
                    ac_path_PYTHON_found=:
                fi
            ])

            if test ${python_status} -eq 0
            then
                # TODO: If "python" is a symlink, resolve the link
                # symlink to at least "python2" or "python3"
                PYTHON="${ac_cv_path_PYTHON}"
                PYTHON_VERSION="${python_info_result}"
                break
            fi
        done

        if test x"${PYTHON}" != "x"
        then
            AC_MSG_RESULT([${PYTHON} (version ${PYTHON_VERSION})])
        elif test "x${ENABLE_PYTHON}" = "x1"
        then
            AC_MSG_RESULT([none found. PySiLK support disabled.])
            ENABLE_PYTHON=0
        else
            AC_MSG_RESULT([none found])
        fi
    fi

    # Now, store result of running ${python_info} in a file that we load
    python_info_result="./python-config.sh"

    # Get the required info from python
    if test "x${ENABLE_PYTHON}" != "x1"
    then
        # even when building without PySiLK support, get version of
        # python to determine the source files for python scripts not
        # related to PySiLK (e.g., rwidsquery).
        ENABLE_PYTHON=0
    else
        if test "x${PYTHON}" = "xno" || test ! -x "${PYTHON}"
        then
            AC_MSG_ERROR([Specified Python program '${PYTHON}' does not exist])
        fi

        if test "x${PYTHON_VERSION}" = "x"
        then
            AC_MSG_FAILURE([PySiLK cannot use the Python program '${PYTHON}'])
        fi

        # remove old script result and unset version (caching old)
        rm -f ${python_info_result}
        py_old_version="${PYTHON_VERSION}"
        PYTHON_VERSION=

        AC_MSG_CHECKING([python embedding settings])

        # run the python-info script
        echo "${as_me}:${LINENO}: PYTHONPREFIX=\"${sk_PYTHONPREFIX}\" PYTHONSITEDIR=\"${sk_PYTHONSITEDIR}\" \"${PYTHON}\" \"${python_info}\" --filename \"${python_info_result}\"" >&AS_MESSAGE_LOG_FD
        PYTHONPREFIX="${sk_PYTHONPREFIX}" PYTHONSITEDIR="${sk_PYTHONSITEDIR}" "${PYTHON}" "${python_info}" --filename "${python_info_result}"
        python_status=$?
        echo "${as_me}:${LINENO}: \$? = ${python_status}" >&AS_MESSAGE_LOG_FD

        # pull in results from the script
        if test ${python_status} -eq 0 && test -f "${python_info_result}"
        then
            . "${python_info_result}"
        else
            AC_MSG_FAILURE([failed to execute '${PYTHON} ${python_info}'])
        fi

        # verify that we have a version
        if test -z "${PYTHON_VERSION}"
        then
            AC_MSG_ERROR([error running '${PYTHON} ${python_info}'])
        fi
        AC_MSG_RESULT([yes])

        # compare Python versions (not expected to happen)
        if test "x${PYTHON_VERSION}" != "x${py_old_version}"
        then
            AC_MSG_NOTICE([(${PACKAGE}) Using ${PYTHON_VERSION} for PySiLK support])
        fi

        #|--# print results
        #|--AC_MSG_CHECKING([for Python site package directory])
        #|--AC_MSG_RESULT(${PYTHON_SITE_PKG})
        #|--
        #|--AC_MSG_CHECKING([for Python CPPFLAGS])
        #|--if test "x${PYTHON_CPPFLAGS}" = "x"
        #|--then
        #|--    AC_MSG_RESULT([none])
        #|--else
        #|--    AC_MSG_RESULT(${PYTHON_CPPFLAGS})
        #|--fi

        #|--AC_MSG_CHECKING([for Python LDFLAGS])
        # Replace Python's version of pthread flags with our own
        if test "x${PYTHON_LDFLAGS_PTHREAD}" != "x"
        then
            if test "x${PYTHON_LDFLAGS}" != "x"
            then
                PYTHON_LDFLAGS="${PYTHON_LDFLAGS} ${PTHREAD_LDFLAGS}"
            else
                PYTHON_LDFLAGS="${PTHREAD_LDFLAGS}"
            fi
        fi
        #|--if test "x${PYTHON_LDFLAGS}" = "x"
        #|--then
        #|--    AC_MSG_RESULT([none])
        #|--else
        #|--    AC_MSG_RESULT(${PYTHON_LDFLAGS})
        #|--fi

        #|--AC_MSG_CHECKING([for Python embedded LDFLAGS])
        if test "x${PYTHON_LDFLAGS_EMBEDDED_PTHREAD}" != "x"
        then
            if test "x${PYTHON_LDFLAGS_EMBEDDED}" != "x"
            then
                PYTHON_LDFLAGS_EMBEDDED="${PYTHON_LDFLAGS_EMBEDDED} ${PTHREAD_LDFLAGS}"
            else
                PYTHON_LDFLAGS_EMBEDDED="${PTHREAD_LDFLAGS}"
            fi
        fi
        #|--if test "x${PYTHON_LDFLAGS_EMBEDDED}" = "x"
        #|--then
        #|--    AC_MSG_RESULT([none])
        #|--else
        #|--    AC_MSG_RESULT(${PYTHON_LDFLAGS_EMBEDDED})
        #|--fi
        #|--
        #|--AC_MSG_CHECKING([for Python shared library filename extension])
        #|--AC_MSG_RESULT(${PYTHON_SO_EXTENSION})

        # verify that the library and header files are usable.  first,
        # cache current values
        sk_save_LDFLAGS="${LDFLAGS}"
        sk_save_LIBS="${LIBS}"
        sk_save_CPPFLAGS="${CPPFLAGS}"

        # add python values

        # We use LIBS here instead of LDFLAGS because some systems
        # (Ubuntu 11.10) require the -lpython<vers> to go after
        # conftest.c i the gcc invocation.  On the other hand, libtool
        # seems to deal with it just fine in the pysilk makefile.
        LIBS="${sk_save_LIBS} ${PYTHON_LDFLAGS_EMBEDDED}"
        CPPFLAGS="${sk_save_CPPFLAGS} ${PYTHON_CPPFLAGS}"

        AC_MSG_CHECKING([usability of ${PYTHON_LIBNAME} library and headers])
        AC_LINK_IFELSE(
            [AC_LANG_PROGRAM([
#define PY_SSIZE_T_CLEAN
#include <Python.h>
                ],[
Py_InitializeEx(1);
                ])],[
            AC_MSG_RESULT([yes])],[
            AC_MSG_RESULT([no])
            AC_MSG_FAILURE([unable to link C program that uses Python functions.  Perhaps Python was built without a shared libpython?  Details are in config.log.])
        ])

        # restore cached values
        LDFLAGS="${sk_save_LDFLAGS}"
        LIBS="${sk_save_LIBS}"
        CPPFLAGS="${sk_save_CPPFLAGS}"

        AC_MSG_CHECKING([for system-specific Python problems])
        if test -n "${PYTHON_ERROR}"
        then
            AC_MSG_ERROR([python error: ${PYTHON_ERROR}])
        fi
        AC_MSG_RESULT([none])

        rm -f ${python_info_result}
        ENABLE_PYTHON=1
    fi

    # Set variables used in the RPM spec file
    if test "x${ENABLE_PYTHON}" = "x1"
    then
        AC_MSG_NOTICE([(${PACKAGE}) Including PySiLK support])
    fi

    if test "x${PYTHON_VERSION}" = "x"
    then
        AC_MSG_NOTICE([(${PACKAGE}) Will not build some scripts which require Python 2.4 or later])
    elif expr "x${PYTHON_VERSION}" : 'x2\.[[45]]' >/dev/null
    then
        AC_MSG_NOTICE([(${PACKAGE}) "make check" will skip daemon tests which require Python 2.6 or later])
    fi

    AC_DEFINE_UNQUOTED([ENABLE_PYTHON], [${ENABLE_PYTHON}],
        [Define to 1 to build with support for Python.])

    # this is true if we are building with python plugin support
    AM_CONDITIONAL([HAVE_PYTHON], [test "x${ENABLE_PYTHON}" = "x1"])

    # determine version of python
    AM_CONDITIONAL([HAVE_PYTHON24],
                   [expr "x${PYTHON_VERSION}" : 'x2\.[[45]]' >/dev/null])
    AM_CONDITIONAL([HAVE_PYTHON30],
                   [expr "x${PYTHON_VERSION}" : 'x3\.' >/dev/null])

    # this is true if python 2.4 or newer was found. this is used to
    # determine whether stand-alone python scripts are built
    AM_CONDITIONAL([HAVE_PYTHONBIN],
                   [expr "x${PYTHON_VERSION}" : 'x[[23]]' >/dev/null ])

])# SILK_AC_PYTHON


# ---------------------------------------------------------------------------
# SILK_AC_PREPROC_ADDITIONAL_FLAGS(var, flag_list)
#
#    For each flag listed in FLAG_LIST, add it to the specified VAR if
#    the preprocessor understands it.
#
AC_DEFUN([SILK_AC_PREPROC_ADDITIONAL_FLAGS],[
    # cache the old CPPFLAGS value
    sk_save_CPPFLAGS="$CPPFLAGS"

    for sk_cpp_flag in $2
    do
        CPPFLAGS="$sk_cpp_flag $sk_save_CPPFLAGS"
        AC_MSG_CHECKING([whether the preprocessor understands $sk_cpp_flag])
        AC_PREPROC_IFELSE(
            [AC_LANG_PROGRAM([],[
                 int x; x++;
                 ])
            ],[
                $1="$$1 $sk_cpp_flag"
                AC_MSG_RESULT([yes])],
            [AC_MSG_RESULT([no])])
    done

    CPPFLAGS="$sk_save_CPPFLAGS"
])#SILK_AC_PREPROC_ADDITIONAL_FLAGS


# ---------------------------------------------------------------------------
# SILK_AC_WARN_TRANSFORM
#
#    Warn about use of --program-prefix, --program-suffix,
#    --program-transform-name
#
AC_DEFUN([SILK_AC_WARN_TRANSFORM],[
    if test "x${program_transform_name}" != "x" && test "x${program_transform_name}" != "xs,x,x,"
    then
        AC_MSG_WARN([[(${PACKAGE}) Use of --program-prefix, --program-suffix, and --program-transform-name are discouraged]])
    fi
])#SILK_AC_WARN_TRANSFORM


# ---------------------------------------------------------------------------
# SILK_AC_WRITE_SUMMARY
#
#    Write a summary of configure to a file
#
AC_DEFUN([SILK_AC_WRITE_SUMMARY],[
    AC_SUBST(SILK_SUMMARY_FILE)
    SILK_SUMMARY_FILE=silk-summary.txt

    # Get the prefix
    sk_summary_prefix="$prefix"
    if test "x$sk_summary_prefix" = xNONE
    then
        sk_summary_prefix="$ac_default_prefix"
    fi

    SILK_FINAL_MSG="
    * Configured package:           ${PACKAGE_STRING}
    * Host type:                    ${build}
    * Source files (\$top_srcdir):   $srcdir
    * Install directory:            $sk_summary_prefix
    * Root of packed data tree:     $SILK_DATA_ROOTDIR"

    if test "x$PACKING_LOGIC_PATH" = "x"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Packing logic:                via run-time plugin"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Packing logic:                $PACKING_LOGIC_PATH"
    fi

    if test "x$ENABLE_LOCALTIME" = "x1"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Timezone support:             local"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Timezone support:             UTC"
    fi

    SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Default compression method:   $ENABLE_OUTPUT_COMPRESSION"

    if test "x$ENABLE_INET6_NETWORKING" = "x1"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPv6 network connections:     YES"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPv6 network connections:     NO"
    fi

    if test "x$ENABLE_IPV6" = "x1"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPv6 flow record support:     YES"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPv6 flow record support:     NO"
    fi

    SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPset file compatibility:     SiLK ${SK_IPSET_COMPATIBILITY} (record-version=${SK_IPSET_DEFAULT_VERSION})"

    if test "x$ENABLE_IPFIX" = "x1"
    then
        sk_msg_ldflags=`echo " $FIXBUF_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="${SILK_FINAL_MSG}
    * IPFIX collection support:     YES${sk_msg_ldflags}
    * NetFlow9 collection support:  YES
    * sFlow collection support:     YES
    * Fixbuf compatibility:         libfixbuf-${libfixbuf_have_version}"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPFIX collection support:     NO
    * NetFlow9 collection support:  NO (No IPFIX support)
    * sFlow collection support:     NO (No IPFIX support)"
    fi



    if test "x$ENABLE_GNUTLS" = "x0"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Transport encryption support: NO (gnutls not found)"
    else
        sk_msg_ldflags=`echo "$GNUTLS_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Transport encryption support: YES$sk_msg_ldflags"
    fi

    if test "x$ENABLE_IPA" = "x1"
    then
        sk_msg_ldflags=`echo "$LIBIPA_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPA support:                  YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * IPA support:                  NO"
    fi

    if test "x$ENABLE_LIBMAXMINDDB" = "x1"
    then
        sk_msg_ldflags=`echo "$LIBMAXMINDDB_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * MaxMindDB support:            YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * MaxMindDB support:            NO"
    fi

    if test "x$ENABLE_ZLIB" = "x1"
    then
        sk_msg_ldflags=`echo "$ZLIB_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * ZLIB support:                 YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * ZLIB support:                 NO"
    fi

    if test "x$ENABLE_LZO" = "x1"
    then
        sk_msg_ldflags=`echo "$LZO_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * LZO support:                  YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * LZO support:                  NO"
    fi

    if test "x$ENABLE_SNAPPY" = "x1"
    then
        sk_msg_ldflags=`echo "$SNAPPY_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * SNAPPY support:               YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * SNAPPY support:               NO"
    fi

    if test "x$ENABLE_PCAP" = "x1"
    then
        sk_msg_ldflags=`echo "$PCAP_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * LIBPCAP support:              YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * LIBPCAP support:              NO"
    fi

    if test "x$ENABLE_CARES" = "x1"
    then
        sk_msg_ldflags=`echo "$CARES_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * C-ARES support:               YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * C-ARES support:               NO"
    fi

    if test "x$ENABLE_ADNS" = "x1"
    then
        sk_msg_ldflags=`echo "$ADNS_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * ADNS support:                 YES$sk_msg_ldflags"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * ADNS support:                 NO"
    fi

        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Python interpreter:           $PYTHON"

    if test "x$ENABLE_PYTHON" = "x1"
    then
        sk_msg_ldflags=`echo "$PYTHON_LDFLAGS_EMBEDDED" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
        if test -n "$sk_msg_ldflags"
        then
            sk_msg_ldflags=" ($sk_msg_ldflags)"
        fi
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Python support:               YES$sk_msg_ldflags
    * Python package destination:   $PYTHON_SITE_PKG"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Python support:               NO"
    fi

#   if test "x$ENABLE_PCRE" = "x1"
#   then
#       sk_msg_ldflags=`echo "$PCRE_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`
#       if test -n "$sk_msg_ldflags"
#       then
#           sk_msg_ldflags=" ($sk_msg_ldflags)"
#       fi
#       SILK_FINAL_MSG="$SILK_FINAL_MSG
#   * PCRE support:                 YES$sk_msg_ldflags"
#   else
#       SILK_FINAL_MSG="$SILK_FINAL_MSG
#   * PCRE support:                 NO"
#   fi

    if test "x$silk_enable_analysis_tools" = "x0"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Build analysis tools:         NO (--disable-analysis-tools)"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Build analysis tools:         YES"
    fi

    if test "x$silk_enable_packing_tools" = "x0"
    then
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Build packing tools:          NO (--disable-packing-tools)"
    else
        SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Build packing tools:          YES"
    fi

    # Remove leading whitespace
    sk_msg_cflags="$SK_SRC_INCLUDES $SK_CPPFLAGS $CPPFLAGS $WARN_CFLAGS $SK_CFLAGS $CFLAGS"
    sk_msg_cflags=`echo "$sk_msg_cflags" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`

    sk_msg_ldflags="$SK_LDFLAGS $LDFLAGS"
    sk_msg_ldflags=`echo "$sk_msg_ldflags" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`

    sk_msg_libs="$LIBS"
    sk_msg_libs=`echo "$sk_msg_libs" | sed 's/^ *//' | sed 's/ *$//' | sed 's/  */ /g'`

    SILK_FINAL_MSG="$SILK_FINAL_MSG
    * Compiler (CC):                $CC
    * Compiler flags (CFLAGS):      $sk_msg_cflags
    * Linker flags (LDFLAGS):       $sk_msg_ldflags
    * Libraries (LIBS):             $sk_msg_libs
"

    echo "$SILK_FINAL_MSG" > $SILK_SUMMARY_FILE

    AC_CONFIG_COMMANDS([silk_summary],[
        if test -f $SILK_SUMMARY_FILE
        then
            cat $SILK_SUMMARY_FILE
        fi],[SILK_SUMMARY_FILE=$SILK_SUMMARY_FILE])

]) # SILK_AC_WRITE_SUMMARY


# ---------------------------------------------------------------------------
# SILK_TEST_SUBST
#
#    Create the substitution variables required by testing framework
#
AC_DEFUN([SILK_TEST_SUBST],[
    AC_SUBST([IS_LITTLE_ENDIAN], [$LITTLE_ENDIAN])
    AC_SUBST([IS_BIG_ENDIAN], [$BIG_ENDIAN])
    AC_SUBST([SK_ENABLE_GNUTLS], [$ENABLE_GNUTLS])
    AC_SUBST([SK_ENABLE_INET6_NETWORKING], [$ENABLE_INET6_NETWORKING])
    AC_SUBST([SK_ENABLE_IPA], [$ENABLE_IPA])
    AC_SUBST([SK_ENABLE_IPFIX], [$ENABLE_IPFIX])
    AC_SUBST([SK_ENABLE_IPV6], [$ENABLE_IPV6])
    AC_SUBST([SK_ENABLE_OUTPUT_COMPRESSION], [$ENABLE_OUTPUT_COMPRESSION])
])# SILK_TEST_SUBST


# ---------------------------------------------------------------------------
# SILK_RPM_SPEC_SUBST
#
#    Create the substitution variables required by the RPM spec file
#
AC_DEFUN([SILK_RPM_SPEC_SUBST],[
    # variables we use when creating the rpm silk.spec file
    RPM_SPEC_REQUIRES=""
    RPM_SPEC_BUILDREQUIRES=""
    RPM_SPEC_CONFIGURE=""

    # check for -DNDEBUG in CPPFLAGS
    if echo " $SK_CPPFLAGS $CPPFLAGS " | grep '/ -DNDEBUG /' >/dev/null 2>&1
    then
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --enable-assert"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --disable-assert"
    fi


    if test "x$ENABLE_IPV6" = "x1"
    then
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --enable-ipv6"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --disable-ipv6"
    fi

    if test "x$ENABLE_INET6_NETWORKING" = "x0"
    then
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --disable-inet6-networking"
    fi

    if test "x${SK_IPSET_DEFAULT_VERSION}" != "x2"
    then
        RPM_SPEC_CONFIGURE="${RPM_SPEC_CONFIGURE} --enable-ipset-compatibilty=${SK_IPSET_COMPATIBILITY}"
    fi

    if test "x$ENABLE_LOCALTIME" = "x1"
    then
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --enable-localtime"
    fi

    RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --enable-output-compression=$sk_output_comp"

    if test "x$ENABLE_ADNS" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES adns,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES adns-devel,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-adns"
    fi

    if test "x$ENABLE_CARES" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES c-ares,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES c-ares-devel,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-c-ares"
    fi

    if test "x$ENABLE_IPFIX" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES libfixbuf >= $libfixbuf_required_version,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES libfixbuf-devel >= $libfixbuf_required_version,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-libfixbuf"
    fi

    if test "x$ENABLE_GNUTLS" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES gnutls >= $gnutls_required_version,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES gnutls-devel >= $gnutls_required_version,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-gnutls"
    fi

    if test "x$ENABLE_IPA" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES libipa >= $libipa_required_version,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES libipa-devel >= $libipa_required_version,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-libipa"
    fi

    if test "x$ENABLE_LIBMAXMINDDB" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES libmaxminddb >= $libmaxminddb_required_version,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES libmaxminddb-devel >= $libmaxminddb_required_version,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-libmaxminddb"
    fi

    if test "x$ENABLE_LZO" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES lzo,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES lzo-devel,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-lzo"
    fi

    if test "x$ENABLE_SNAPPY" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES snappy,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES snappy-devel,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-snappy"
    fi

    if test "x$ENABLE_PCAP" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES libpcap,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES "'%{_includedir}/pcap.h,'
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-pcap"
    fi

    if test "x$ENABLE_ZLIB" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES zlib,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES zlib-devel,"
    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-zlib"
    fi

    # Set variables used in the RPM spec file
    if test "x$ENABLE_PYTHON" = "x1"
    then
        RPM_SPEC_REQUIRES="$RPM_SPEC_REQUIRES python >= 2.4,"
        RPM_SPEC_BUILDREQUIRES="$RPM_SPEC_BUILDREQUIRES python-devel >= 2.4,"
        RPM_SPEC_WITH_PYTHON=1

        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --with-python='${PYTHON}'"
        if test "x$sk_PYTHONPREFIX" != "x"
        then
            RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --with-python-prefix='$sk_PYTHONPREFIX'"
        elif test "x$sk_PYTHONSITEDIR" != "x"
        then
            RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --with-python-site-dir='$sk_PYTHONSITEDIR'"
        fi

        # Where we finally want them to be installed.
        # Change '\$' to '%' for the spec file.
        RPM_SPEC_PYTHON_SITEPKG=`echo "${PYTHON_SITE_PKG}" | sed 's/\\$/%/g'`
        RPM_SPEC_PYTHON_SITEPKG_SILK=`echo "${PYTHON_SITE_PKG}/${PACKAGE}" | sed 's/\\$/%/g'`

    else
        RPM_SPEC_CONFIGURE="$RPM_SPEC_CONFIGURE --without-python"
        RPM_SPEC_WITH_PYTHON=0
        RPM_SPEC_PYTHON_SITEPKG_SILK=NONE
    fi

    # remove trailing comma
    RPM_SPEC_REQUIRES=`echo "$RPM_SPEC_REQUIRES" | sed 's/,$//'`
    RPM_SPEC_BUILDREQUIRES=`echo "$RPM_SPEC_BUILDREQUIRES" | sed 's/,$//'`

    AC_SUBST(RPM_SPEC_REQUIRES)
    AC_SUBST(RPM_SPEC_BUILDREQUIRES)
    AC_SUBST(RPM_SPEC_CONFIGURE)

    # Variables we need to use in the silk.spec file for RPM
    AC_SUBST(RPM_SPEC_WITH_PYTHON)
    AC_SUBST(RPM_SPEC_PYTHON_SITEPKG)
    AC_SUBST(RPM_SPEC_PYTHON_SITEPKG_SILK)

])#SILK_RPM_SPEC_REQUIRES

dnl Local Variables:
dnl mode:autoconf
dnl indent-tabs-mode:nil
dnl End:
