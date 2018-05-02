dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl configure.in
dnl autotools build system for YAF applications
dnl ------------------------------------------------------------------------
dnl Copyright (C) 2005-2018 Carnegie Mellon University. All Rights Reserved.
dnl ------------------------------------------------------------------------
dnl Authors: Brian Trammell
dnl ------------------------------------------------------------------------
dnl GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
dnl ------------------------------------------------------------------------

dnl RCSIDENT("$Id$")

AC_INIT([yaf], [2.9.4], [netsa-help@cert.org],[yaf])
AC_CONFIG_AUX_DIR([autoconf])
AC_COPYRIGHT([Copyright (C) 2006-2017 by Carnegie Mellon University
GNU Public License (GPL) Rights pursuant to Version 2, June 1991
Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013])
AC_CANONICAL_BUILD
AC_CANONICAL_HOST
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.6.3 foreign subdir-objects])
LIBCOMPAT="4:0:0"
AC_REVISION($Revision$)
AC_CONFIG_HEADERS(include/yaf/config.h)
AC_CONFIG_HEADERS(airframe/include/airframe/config.h)

RPM_CONFIG_FLAGS=""
OPTION_CONFIG_STRING="build configuration: "


dnl ----------------------------------------------------------------------
dnl Check for (or install) libltdl #AC_LIBTOOL_DLOPEN
dnl ----------------------------------------------------------------------

AC_LIBTOOL_DLOPEN

AC_PATH_LIBLTDL

AC_PROG_LIBTOOL

AC_CONFIG_SUBDIRS(libltdl)

dnl -------------------------------------
dnl set version of plugins
dnl -------------------------------------
version_info="1:1:0"
AC_SUBST([version_info])

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_HEADER_STDC
AC_LANG([C])

dnl ----------------------------------------------------------------------
dnl Set up doxygen
dnl ----------------------------------------------------------------------

DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(OFF)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(yaf, Doxyfile, doc)

dnl and then there was an ancient version of redhate, AS4
dnl AC_PROG_CC_C99

if test "x$CPPFLAGS" == "x"; then
    CPPFLAGS='-Wall -Wno-comment -Wno-long-long'
fi
CPPFLAGS='-I$(top_builddir)/include -I$(top_srcdir)/include -I$(top_builddir)/airframe/include -I$(top_srcdir)/airframe/include'" $CPPFLAGS"

AC_HEADER_DIRENT
AC_HEADER_SYS_WAIT
AC_HEADER_TIME

AC_CHECK_HEADERS([errno.h fcntl.h glob.h signal.h sys/errno.h grp.h malloc.h])
AC_CHECK_HEADERS([netdb.h netinet/in.h pwd.h stdarg.h stddef.h sys/socket.h syslog.h])
AC_CHECK_HEADERS([inttypes.h limits.h ctype.h stdlib.h search.h math.h])


AC_SEARCH_LIBS([nanosleep], [rt])
AC_SEARCH_LIBS([inet_ntoa], [nsl])
AC_SEARCH_LIBS([socket], [socket])
AC_SEARCH_LIBS([log], [m])

AC_SUBST(YAF_REQ_AIRFRAME_VER, [2.0.0])

dnl ----------------------------------------------------------------------
dnl Set up pod2man
dnl ----------------------------------------------------------------------

AC_CHECK_PROGS(POD2MAN, [pod2man true])

YAF_POD2MAN_ARGS="--center='Yet Another Flowmeter' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"
AIRFRAME_POD2MAN_ARGS="--center='airframe' --release='"${PACKAGE_VERSION}"' --date='"`date +"%v"`"'"

AC_SUBST(YAF_POD2MAN_ARGS)
AC_SUBST(AIRFRAME_POD2MAN_ARGS)

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
dnl Set up pod2html
dnl ----------------------------------------------------------------------
AC_CHECK_PROGS(POD2HTML,pod2html)

dnl ----------------------------------------------------------------------
dnl Check for aligned access required
dnl ----------------------------------------------------------------------

AX_CHECK_ALIGNED_ACCESS_REQUIRED

AC_CHECK_SIZEOF([int *])

dnl ----------------------------------------------------------------------
dnl for some reason prefix doesn't get set here - so this is a nice hack
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

AM_PATH_GLIB_2_0([2.4.7],[GLIB_PRESENT=YES])

AC_ARG_WITH(glib-static,
AS_HELP_STRING([--with-glib-static=prefix],[use static glib tree]),[
GLIB_STATIC_LIBGLIB2_A="${withval}/lib/libglib-2.0.a"
GLIB_STATIC_INCLUDE="${withval}/include/glib-2.0"
GLIB_STATIC_LIBINCLUDE="${withval}/lib/glib-2.0/include"
if test -f ${GLIB_STATIC_LIBGLIB2_A}; then
    if test -f "${GLIB_STATIC_INCLUDE}/glib.h"; then
        GLIB_LDADD=${GLIB_STATIC_LIBGLIB2_A}
        GLIB_CFLAGS="-I${GLIB_STATIC_INCLUDE} -I${GLIB_STATIC_LIBINCLUDE}"
        AC_SUBST(GLIB_LIBS)
        AC_SUBST(GLIB_CFLAGS)
        GLIB_PRESENT=YES
        AC_MSG_NOTICE([assuming static glib in ${withval} is good...])
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"glib from ${withval} |"
    fi
fi
])

if test x"$GLIB_PRESENT" != "xYES"; then
  AC_MSG_ERROR([Cannot find a suitable glib2 (>= 2.4.7)])
fi

AC_SUBST(GLIB_LDADD)
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)
AC_SUBST(LIBLTDL)
AC_SUBST(LTDLINCL)

use_popt=no

AC_ARG_WITH(popt, AS_HELP_STRING([--with-popt=path],[location of popt]),
[
    use_popt=yes
    if test "x${with_popt}" == "x"; then
         if test -d ${withval}; then
             POPT_CLFAGS="-I${withval}/include"
             POPT_LDFLAGS="-L${withval}/lib -lpopt"
             CFLAGS="$CFLAGS ${POPT_CFLAGS}"
             CPPFLAGS="$CFLAGS ${POPT_CFLAGS}"
             LDFLAGS="$LDFLAGS ${POPT_LDFLAGS}"
         fi
    fi
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-popt=${with_popt}"
])

if test "x$use_popt" = "xyes"; then
    AC_CHECK_LIB(popt,poptParseArgvString, [
        AC_MSG_NOTICE([using libpopt found in ${with_popt} for options processing])
        AC_DEFINE([USE_POPT], 1,
          [Define to 1 to use libpopt])
          OPTION_CONFIG_SRING=${OPTION_CONFIG_STRING}"popt from ${with_popt} |"],[
            AC_MSG_ERROR([libpopt was not found or is not usable])
        ]
    )
else
    if $PKG_CONFIG --atleast-version 2.6.4 glib-2.0 >/dev/null 2>&1 ; then
        AC_MSG_NOTICE([using GLib for options processing])
        AC_DEFINE(USE_GOPTION, 1, [Define to 1 to enable use of GOption])
        AC_SUBST(YAF_REQ_GLIB_VER, [2.6.4])
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"glib opt processing|"
    else
        AC_SUBST(YAF_REQ_GLIB_VER, [2.4.7])
        AC_CHECK_LIB(popt,poptParseArgvString, [
            AC_MSG_NOTICE([using libpopt found in ${with_popt} for options processing])
            POPT_LDFLAGS="-lpopt"
            LDFLAGS="$LDFLAGS ${POPT_LDFLAGS}"
            AC_DEFINE([USE_POPT], 1,
              [Define to 1 to use libpopt])
              OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"popt from ${with_popt}|"],[
                AC_MSG_ERROR([Unable to find a suitable library for options processing])
            ]
        )
    fi
fi

dnl ----------------------------------------------------------------------
dnl figure out the right format string for printing size_t
dnl ----------------------------------------------------------------------
YF_SIZE_T_FORMAT



dnl ----------------------------------------------------------------------
dnl Check for libfixbuf
dnl when changing the version number required, do both the subst, and
dnl package lines!
dnl ----------------------------------------------------------------------
AC_SUBST(YAF_REQ_FIXBUF_VER, [2.0.0])
PKG_CHECK_MODULES(libfixbuf, [libfixbuf >= 2.0.0 libfixbuf < 3.0.0],
                  [
                    YF_PKGCONFIG_VERSION(libfixbuf)
                    YF_PKGCONFIG_LPATH(libfixbuf)
                    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"fixbuf "${yfpkg_ver}" "${yfpkg_lpath}"|"
                  ],
                  [AC_MSG_ERROR([Cannot find a suitable libfixbuf (>= 2.0.0) (Try setting PKG_CONFIG_PATH): $libfixbuf_PKG_ERRORS])
])
YF_PKGCONFIG_VERSION(libfixbuf)
fixbuf_install_loc=`$PKG_CONFIG --variable=prefix libfixbuf`
AC_MSG_NOTICE([libfixbuf version: $yfpkg_ver])
AC_MSG_NOTICE([Using libfixbuf installed in: $fixbuf_install_loc])
AC_DEFINE_UNQUOTED([FIXBUF_VERSION], ["$yfpkg_ver"], [fixbuf version])
fixbuf_version=$yfpkg_ver


AC_ARG_ENABLE(ndpi,
        AS_HELP_STRING([--enable-ndpi], [Enable NDPI application labeling]),[
        PKG_CHECK_MODULES(libndpi, [libndpi >= 1.7.0 libndpi < 1.8.0],
        [
        YF_PKGCONFIG_VERSION(libndpi)
        YF_PKGCONFIG_LPATH(libndpi)
        ndpi=true
        AC_DEFINE(YAF_ENABLE_NDPI, 1, [Define to 1 to enable ndpi])
        ],
        [
        AC_MSG_ERROR([Cannot find a suitable libndpi (>= 1.7.0 and < 1.8.0) (Try setting PKG_CONFIG_PATH): $libndpi_PKG_ERRORS])
])])

dnl ----------------------------------------------------------------------
dnl Check for libpcap
dnl ----------------------------------------------------------------------
AC_ARG_WITH(libpcap,
    AS_HELP_STRING([--with-libpcap=PCAP_DIR],[find pcap.h in PCAP_DIR/include, libpcap in PCAP_DIR/lib]),[
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
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"libpcap from ${withval}|"
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-libpcap=${withval}"
        fi
        if test "x$target_os" = "xcygwin"; then
                AC_CHECK_LIB(wpcap,pcap_open_offline,,
                        [AC_MSG_ERROR([cannot locate required WPCAP library])]
                )
        else
                AC_CHECK_LIB(pcap,pcap_open_offline, ,
                        [AC_MSG_ERROR([cannot locate required PCAP library])]
                )
        fi
        AC_CHECK_HEADERS(pcap.h,[],
           [AC_MSG_ERROR([cannot locate required pcap.h header file])]
        )
    fi
    ],[
        if test "x$target_os" = "xcygwin"; then
                AC_CHECK_LIB(wpcap, pcap_open_offline, ,
                    [AC_MSG_ERROR([cannot locate required PCAP library, try the --with-libpcap option])]
                )
        else
                AC_CHECK_LIB(pcap, pcap_open_offline, ,
                    [AC_MSG_ERROR([cannot locate required PCAP library, try the --with-libpcap option])]
                )
        fi
        AC_CHECK_HEADERS(pcap.h,
            [],
            [AC_MSG_ERROR([cannot locate the required pcap.h header file])]
        )
    ]
)

dnl ---------------------------------------------------------------------
dnl Check for pfring
dnl ---------------------------------------------------------------------
AC_ARG_WITH(pfring,
        AS_HELP_STRING([--with-pfring=PFRING_DIR],[find pfring.h in PFRING_DIR/include, libpfring in PFRING_DIR/lib]),[
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

           AC_CHECK_LIB(pfring,pfring_zc_numa_get_cpu_node,[
                        AC_DEFINE(YAF_ENABLE_PFRING, 1, [Define to 1 to enable PFRING support])
                        AC_SUBST(YAF_HAS_PFRING, [1])
                        AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES,1,[Define to 1 to enable YAF Separate Interface Support])
                        AC_DEFINE(YAF_ENABLE_PFRINGZC, 1, [Define to 1 to enable PFRING ZC support])
                        pfringzc=true
                        pfring=true
                        ],
                        [AC_MSG_NOTICE([Cannot locate PFRING ZC library v. 6.2.0 or greater])
                        pfringzc=false
                        pfring=false])
           AC_CHECK_HEADERS(pfring.h,[],
                [AC_MSG_ERROR([cannot open PFRING header file])
                pfring=false])
           AC_CHECK_HEADERS(pfring_zc.h,
                [AC_DEFINE(YAF_ENABLE_PFRINGZC, 1, [Define to 1 to enable PFRING ZC support])],
                [AC_MSG_NOTICE([cannot open PFRING ZC header file])
                pfringzc=false
                AC_DEFINE(YAF_ENABLE_PFRINGZC, 0, [Define to 1 to enable PFRING ZC support])
                ])

        fi
      ]
)
AM_CONDITIONAL([HASPFRINGZC], [test x$pfringzc = xtrue])



dnl ----------------------------------------------------------------------
dnl Check for libdag
dnl ----------------------------------------------------------------------

AC_ARG_WITH(dag,
AS_HELP_STRING([--with-dag=prefix],[include Endace DAG support]),[
if test "x$withval" != "xno"; then
   AC_SUBST(DAG_LDFLAGS)
  if test -d ${withval}; then
    DAG_LDFLAGS="-L${withval}/lib"
    LDFLAGS="$DAG_LDFLAGS ${LDFLAGS}"
    CFLAGS="-I${withval}/include ${CFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-dag=${withval}"
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"dag library ${withval}|"
  fi

    dnl look for libdag
    AC_CHECK_LIB(dag, dag_open,[
        AC_DEFINE(YAF_ENABLE_DAG, 1, [Define to 1 to enable DAG support])
        AC_SUBST(YAF_HAS_DAG, [1])
       AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES, 1, [Define to 1 to enable recording interface numbers])
        interface=true
        LIBS="-ldag ${LIBS}"
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-dag"
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"dag library ${LIBS}|"
    ],[
        AC_MSG_ERROR([--with-dag given but cannot find libdag])
        dagapi=false
    ])

    AC_CHECK_HEADER(dagapi.h,,[
        AC_MSG_ERROR([--with-dag given but cannot find dagapi.h])
        dagapi=false
    ])
fi
])

dnl ----------------------------------------------------------------------
dnl Check for libpntapi
dnl ----------------------------------------------------------------------
AC_ARG_WITH(napatech,
    AS_HELP_STRING([--with-napatech=NT_DIR],[include Napatech support (find nt.h in NT_DIR/include, libntapi in NT_DIR/lib)]),[
    if test "x$withval" != "xno"; then
      if test -d ${withval}; then
        LDFLAGS="-L${withval}/lib ${LDFLAGS}"
        CFLAGS="-I${withval}/include ${CFLAGS} -pthread"
        CPPFLAGS="-I${withval}/include ${CPPFLAGS}"
        LIBS="-L${withval}/lib -pthread -lntapi $LIBS"
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-napatech=${withval}"
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}" napatech library ${withval}|"
      fi
    AC_CHECK_LIB([ntapi],[NT_Init],[
       AC_DEFINE(YAF_ENABLE_NAPATECH, 1, [Define to 1 to enable Napatech support])
       AC_SUBST(YAF_HAS_NAPATECH, [1])
       AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES, 1, [Define to 1 to enable recording interface numbers])
       interface=true
       LIBS="-lntapi -pthread ${LIBS}"
       RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-napatech"
       OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}" napatech library ${LIBS}|"
       napapi=true
       ]
     ,[
       AC_MSG_ERROR([--with-napatech given but cannot find libntapi.  May need to set LDFLAGS to napatech library.])
       napapi=false
     ])
     AC_CHECK_HEADER(nt.h,,[
       AC_MSG_ERROR([--with-napatech given but cannot find nt.h])
       napapi=false
     ])
   fi
   ]
)


dnl ----------------------------------------------------------------------
dnl Check for nfe_packetcap.h for Netronome support
dnl ----------------------------------------------------------------------
AC_ARG_WITH(netronome,
AS_HELP_STRING([--with-netronome=prefix],[include Netronome API support]),[
if test "x$withval" != "xno"; then

  if test -d ${withval}; then
    CFLAGS="-I${withval}/include ${CFLAGS}"
    CPPFLAGS="-I{withval}/include ${CPPFLAGS}"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-netronome=${withval}"
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"netronome ${withval}|"
  fi

    dnl look for libnfp
    AC_CHECK_HEADER(nfe_packetcap.h,[
        AC_DEFINE(YAF_ENABLE_NETRONOME, 1, [Define to 1 to enable Netronome support])
        AC_SUBST(YAF_HAS_NETRONOME, [1])
       AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES, 1, [Define to 1 to enable recording interface numbers])
        interface=true
        nfeapi=true
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-netronome"
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"Netronome|"
    ],[
        AC_MSG_ERROR([--with-netronome given but cannot find nfe_packetcap.h])
        nfeapi=false
    ],[
    [#if HAVE_NFE_PACKETCAP_H
    #include <nfe_packetcap.h>
    #endif
    ]])

fi
])


dnl ----------------------------------------------------------------------
dnl Check for pcap-zcopy.h
dnl ----------------------------------------------------------------------
AC_ARG_WITH(bivio,
AS_HELP_STRING([--with-bivio=PCAP_ZCOPY_DIR],[include Bivio support (find pcap-zcopy.h in PCAP_ZCOPY_DIR/include)]),[
    if test "x$withval" != "xno"; then
      if test -d ${withval}; then
        CFLAGS="-I${withval}/include ${CFLAGS}"
      fi
     AC_CHECK_HEADERS(pcap-zcopy.h,[
       AC_DEFINE(YAF_ENABLE_BIVIO,1,[Define to 1 to enable BIVIO support])
       AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES,1,[Define to 1 to enable YAF Separate Interface Support])
       interface=true
        RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --with-bivio=${withval}"
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}" bivio ${withval}|"
        biviozcopy=true
       ],[
       AC_MSG_ERROR([--with-bivio given but cannot find pcap-zcopy.h])
       biviozcopy=false
     ],
     [#ifdef HAVE_PCAP_H
      #include <pcap.h>
      #endif
     ])
   fi
])

dnl ----------------------------------------------------------------------
dnl Enable optional flow table features
dnl ----------------------------------------------------------------------

AC_ARG_ENABLE(compact-ip4,
AS_HELP_STRING([--disable-compact-ip4],
               [Use full address structure in flow table]),[
if test "x$enableval" = "xno"; then
    AC_MSG_NOTICE([Disabling compact IPv4 addresses in flow table])
    AC_DEFINE(YAF_ENABLE_COMPACT_IP4, 0,
              [Define to 1 to compact IPv4 addresses where possible])
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"not-compact IPv4|"
    RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-compact-ip4"
    compact_v4=false
else
    AC_DEFINE(YAF_ENABLE_COMPACT_IP4, 1,
              [Define to 1 to compact IPv4 addresses where possible])
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"compact IPv4|"
    compact_v4=true
fi
],[
    AC_DEFINE(YAF_ENABLE_COMPACT_IP4, 1,
              [Define to 1 to compact IPv4 addresses where possible])
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"compact IPv4|"
    compact_v4=true
])

dnl ----------------------------------------------------------------------
dnl Check for getaddrinfo
dnl ----------------------------------------------------------------------
AC_CHECK_FUNCS(getaddrinfo)

dnl ----------------------------------------------------------------------
dnl see if the user wants to enable hooks/plugins
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(plugins,
        AC_HELP_STRING([--enable-plugins], [enable YAF to load plugin extensions (default is no)]),
        [
      AC_DEFINE(YAF_ENABLE_HOOKS, 1, [Define to 1 to enable plugin support])
                plugins=true
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"Plugin Support |"
                RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-plugins"
                AC_SUBST(YAF_REQ_PLUG_CONF, [1])
        ],
        [
                plugins=false
        ]
)
AM_CONDITIONAL([PLUGINENABLE], [test x$plugins = xtrue])

dnl ----------------------------------------------------------------------
dnl Check for PCRE library, needed for the application labeler engine
dnl ----------------------------------------------------------------------
AC_SUBST(YAF_REQ_PCRE_VER, [7.3])
PKG_CHECK_MODULES(pcreLib, [libpcre >= 7.3],
    [
        AC_DEFINE(HAVE_PCRE, 1, [Define to 1 to enable PCRE support])
        LDFLAGS="$LDFLAGS $pcreLib_LIBS"
        CFLAGS="$CFLAGS $pcreLib_CFLAGS"
        pcreexist=true
        AC_MSG_NOTICE([PCRE found and added to build])
        YF_LIBSTR_STRIP(${LDFLAGS})
        AC_SUBST(YAF_PC_PCRE, [", libpcre >= 7.3"])
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"PCRE available ${yf_libstr}|"
    ],[
        AC_MSG_WARN([The application labeler engine requires the PCRE library >= 7.3 to operate, you can set the PKG_CONFIG_PATH variable to help find it])
        pcreexist=false
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"PCRE unavailable|"
    ]
)
AM_CONDITIONAL([PCREEXISTS], [test x$pcreexist = xtrue])



dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the application labeler
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(applabel,
    AC_HELP_STRING([--enable-applabel], [enable the packet payload application label engine (default is no) requires PCRE library]),
    [
            if test "x$enableval" = "xno"; then
                AC_MSG_NOTICE([Disabling the application labeler])
                applabeler=false
            else
            AC_DEFINE(YAF_ENABLE_APPLABEL, 1, [Define to 1 to enable application labeler engine])
            applabeler=true
            if test "x$pcreexist" != "xtrue"; then
                AC_MSG_ERROR([The application labeler cannot be enabled if the PCRE library is not available])
            fi
            if test "x$nopayload" == "xtrue"; then
                AC_MSG_ERROR([The application labeler cannot be enabled if the payload processing is disabled])
            fi
                AC_MSG_NOTICE([Application labeler is enabled])
            AC_SUBST(YAF_REQ_PCRE, [1])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-applabel"
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"applabeling|"
        fi
    ],
    [
        applabeler=false
        AC_MSG_NOTICE([Application labeler is disabled by default])
    ]
)
AM_CONDITIONAL([APPLABELENABLE], [test x$applabeler = xtrue])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of DNS Authoritative Resp ONLY
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(exportDNSAuth,
        AC_HELP_STRING([--enable-exportDNSAuth], [enable export of DNS Authoritative Responses Only (default is export everything)]),
        [
                if test "x$enableval" = "xno"; then
                   AC_MSG_NOTICE([Enabling export of all DNS Responses])
                   exportDNSAuth = false
                else
                AC_DEFINE(YAF_ENABLE_DNSAUTH, 1, [Define to 1 to enable export of DNS Authoritative Responses Only])
                exportDNSAuth=true
                if test "x$plugins" != "xtrue"; then
                   AC_MSG_ERROR([DNS Authoritative Response Export requires plugins to be enabled])
                fi
                if test "x$applabeler" != "xtrue"; then
                   AC_MSG_ERROR([Application labeling must be enabled to export DNS Authoritative Responses])
                fi
                   AC_MSG_NOTICE([Export only DNS Authoritative Responses is enabled])
          fi
        ],
        [
         exportDNSAuth=false
         AC_MSG_NOTICE([Enable Export of DNS Authoritative Responses is disabled by default])
        ]

)
AM_CONDITIONAL([EXPORTDNSAUTH], [test x$exportDNSAuth = xtrue])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of DNS NXDOMAIN Responses ONLY
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(exportDNSNXDomain,
        AC_HELP_STRING([--enable-exportDNSNXDomain], [enable export of DNS NXDomain Responses Only (default is export everything)]),
        [
                if test "x$enableval" = "xno"; then
                   AC_MSG_NOTICE([Enabling export of all DNS Responses])
                   exportDNSNXDomain = false
                else
                AC_DEFINE(YAF_ENABLE_DNSNXDOMAIN, 1, [Define to 1 to enable export of DNS NXDomain Responses Only])
                exportDNSNXDomain=true
                if test "x$plugins" != "xtrue"; then
                   AC_MSG_ERROR([DNS NXDomain Response Export requires plugins to be enabled])
                fi
                if test "x$applabeler" != "xtrue"; then
                   AC_MSG_ERROR([Application labeling must be enabled to export DNS Authoritative Responses])
                fi
                   AC_MSG_NOTICE([Export only DNS NXDomain Responses is enabled])
          fi
        ],
        [
         exportDNSNXDomain=false
         AC_MSG_NOTICE([Enable Export of DNS NXDomain Responses is disabled by default])
        ]

)
AM_CONDITIONAL([EXPORTDNSNXDomain], [test x$exportDNSNXDomain = xtrue])

dnl ----------------------------------------------------------------------
dnl check for disabling all payload handling
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(payload,
    AC_HELP_STRING([--disable-payload], [disable YAF from being built with payload handling capability]),
    [
        if test "x$enableval" = "xno"; then
            if test "x$applabeler" == "xtrue"; then
                AC_MSG_ERROR([Cannot disable payload and enable application labeling])
            fi
            AC_DEFINE(YAF_ENABLE_PAYLOAD, 0, [Define to 1 to enable yaf payload processing])
            nopayload=true
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-payload"
            AC_MSG_NOTICE([YAF payload processing is disabled])
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"no payload processing|"
        else
            AC_MSG_NOTICE([YAF payload processing is not disabled])
            nopayload=false
            AC_DEFINE(YAF_ENABLE_PAYLOAD, 1, [Define to 1 to enable yaf payload processing])
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"payload processing|"
        fi
    ],
    [
        AC_DEFINE(YAF_ENABLE_PAYLOAD, 1, [Define to 1 to enable yaf payload processing])
        AC_MSG_NOTICE([Payload processing is enabled by default])
        nopayload=false
        OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"payload processing|"
    ]
)


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the entropy calculator
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(entropy,
    AC_HELP_STRING([--enable-entropy], [enable the packet payload entropy calculation]),
    [
            if test "x$enableval" = "xno"; then
                AC_MSG_NOTICE([Disabling the entropy calculator])
                entropycalc=false
            else
            AC_DEFINE(YAF_ENABLE_ENTROPY, 1, [Define to 1 to enable entropy calculator])
            entropycalc=true
            if test "x$nopayload" == "xtrue"; then
                AC_MSG_ERROR([The entropy calculator cannot be enabled if the payload processing is disabled])
            fi
                AC_MSG_NOTICE([Entropy calculator is enabled])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-entropy"
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"entropy|"
        fi
    ],
    [
        AC_MSG_NOTICE([Entropy calculator disabled by default])
        entropycalc=false
    ]
)


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the DAG interface hack
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(daginterface,
    AC_HELP_STRING([--enable-daginterface], [enable encoding DAG interface numbers into the record output]),
    [
        if test "x$enableval" = "xno"; then
            AC_MSG_NOTICE([Disabling the DAG interface numbers recording])
            daginterfacehack=false
        else
            AC_DEFINE(YAF_ENABLE_DAG_SEPARATE_INTERFACES, 1, [Define to 1 to enable recording DAG interface numbers])
            daginterfacehack=true
            AC_MSG_NOTICE([DAG interface recording into output records is enabled])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-daginterface"
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"DAG interface labeling|"
        fi
    ],
    [
        AC_MSG_NOTICE([DAG interface recording into output record disabled by default])
        daginterfacehack=false
    ]
)

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the Napatech interface hack
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(interface,
    AC_HELP_STRING([--enable-interface], [enable encoding Napatech/Netronome/DAG interface numbers into the record output (on by default)]),
    [
        if test "x$enableval" = "xno"; then
            AC_MSG_NOTICE([Disabling the interface numbers recording])
            interface=false
        else
            AC_DEFINE(YAF_ENABLE_SEPARATE_INTERFACES, 1, [Define to 1 to enable recording interface numbers])
            interface=true
            AC_MSG_NOTICE([Interface recording into output records is enabled])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-interface"
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"interface labeling|"
        fi
    ]
)


dnl ----------------------------------------------------------------------
dnl check if the user wants to enable export of handshake headers
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(fpexporter,
    AC_HELP_STRING([--enable-fpexporter], [enable export of handshake headers for external fingerprinting, default is off]),
    [
           if test "x$enableval" = "xno"; then
              AC_MSG_NOTICE([Disabling the fingerprint exporter])
              fp_exporter = false
           else
           AC_DEFINE(YAF_ENABLE_FPEXPORT, 1, [Define to 1 to enable fingerprint exporter])
           fp_exporter=true
           AC_MSG_NOTICE([Fingerprint exporter is enabled])
           RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-fpexporter"
           OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"fingerprint export|"
        fi
     ],
     [
       fp_exporter=false
       AC_MSG_NOTICE([fingerprint exporter disabled by default])
     ]
)
AM_CONDITIONAL([FPEXPORT], [test x$fp_exporter = xtrue])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable the p0f based finger printer
dnl ----------------------------------------------------------------------
p0f_printer=
AC_ARG_ENABLE(p0fprinter,
    AC_HELP_STRING([--enable-p0fprinter], [enable the p0f based OS finger printing capability, default is off]),
    [
            if test "x$enableval" = "xno"; then
                AC_MSG_NOTICE([Disabling the p0f fingerprinter])
                p0f_printer=false
            else
            AC_DEFINE(YAF_ENABLE_P0F, 1, [Define to 1 to enable p0f OS fingerprinter])
            p0f_printer=true
            if test "x$applabeler" != "xtrue"; then
                AC_MSG_ERROR([The p0f finger printer cannot be enabled if the application labeler is not also enabled])
            fi
            AC_MSG_NOTICE([p0f based OS finger printer is enabled])
            RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-p0fprinter"
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"p0f labeling|"
            AC_SUBST(YAF_REQ_P0F_CONF, [1])
        fi
    ],
    [
        p0f_printer=false
        AC_MSG_NOTICE([p0f based OS fingerprinter disabled by default])
    ]
)
AM_CONDITIONAL([P0FENABLE], [test x$p0f_printer = xtrue])

if test "x$p0f_printer" = "xtrue"; then
   AC_SUBST(YAF_REQ_P0F_VER, [2.0.8])
   PKG_CHECK_MODULES(libp0f, [libp0f >= 2.0.8],
                  [
                    YF_PKGCONFIG_VERSION(libp0f)
                    YF_PKGCONFIG_LPATH(libp0f)
                  ],
                  [AC_MSG_ERROR([Cannot find a suitable libp0f (>= 2.0.8): $libp0f_PKG_ERRORS])
])
fi

dnl ----------------------------------------------------------------------
dnl check if the user wants to support MPLS netflow
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(mpls,
    AC_HELP_STRING([--enable-mpls], [enable MPLS label hashing and export (default is no)]),
    [
            if test "x$enableval" = "xno"; then
                AC_MSG_NOTICE([Disabling MPLS support])
                mpls=false
            else
                AC_DEFINE(YAF_MPLS, 1, [Define to 1 to enable mpls support])
                mpls=true
                AC_MSG_NOTICE([MPLS Flow is enabled])
                RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-mpls"
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"mpls enabled|"
            fi
    ],
    [
        mpls=false
        AC_MSG_NOTICE([MPLS Flow is disabled by default])
    ]
)
AM_CONDITIONAL([MPLSENABLE], [test x$mpls = xtrue])

dnl ----------------------------------------------------------------------
dnl check if the user wants to enable non-IP flow data
dnl ----------------------------------------------------------------------
AC_ARG_ENABLE(nonip,
    AC_HELP_STRING([--enable-nonip], [enable non-IP data decode and flow export]),
    [
            if test "x$enableval" = "xno"; then
                AC_MSG_NOTICE([Disabling Non-IP flow data])
                nonip=false
            else
                AC_DEFINE(YAF_NONIP, 1, [Define to 1 to enable non-IP flow data export])
                if test "x$mpls" != "xtrue"; then
                    AC_MSG_ERROR([Non-IP data decode and flow export requires --enable-mpls])
                fi
                nonip=true
                AC_MSG_NOTICE([Enabling NON-IP data decode and export])
                RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --enable-nonip"
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"nonip|"
            fi
    ],
    [
        nonip=false
        AC_MSG_NOTICE([Non-IP Flow is disabled by default])
    ]
)
AM_CONDITIONAL([NONIPENABLE], [test x$nonip = xtrue])

dnl ----------------------------------------------------------------------
dnl check for disabling export of type information via (RFC 5610) and
dnl template metadata information
dnl ----------------------------------------------------------------------
AC_MSG_NOTICE([Fixbuf version: $fixbuf_version])
AC_MSG_NOTICE($fixbuf_version)
AX_COMPARE_VERSION($fixbuf_version, [ge], [1.8.0],
[
    AC_ARG_ENABLE(type-export,
        AC_HELP_STRING([--disable-type-export], [disable exporting of options records for enterprise-specific information elements]),
        [
            if test "x$enableval" = "xno"; then
                AC_DEFINE(YAF_ENABLE_METADATA_EXPORT, 0, [Define to 1 to enable yaf metadata export])
                type_export=false
                RPM_CONFIG_FLAGS="${RPM_CONFIG_FLAGS} --disable-type-export"
                AC_MSG_NOTICE([type export is disabled])
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"no type export|"
            else
                AC_MSG_NOTICE([type export is not disabled])
                type_export=true
                AC_DEFINE(YAF_ENABLE_METADATA_EXPORT, 1, [Define to 1 to enable yaf metadata export])
                OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
            fi
        ],
        [
            AC_DEFINE(YAF_ENABLE_METADATA_EXPORT, 1, [Define to 1 to enable yaf metadata export])
            AC_MSG_NOTICE([Metadata export is enabled by default])
            type_export=true
            OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
        ]
    )
],[
    AC_DEFINE(YAF_ENABLE_METADATA_EXPORT, 0, [Define to 1 to enable yaf metadata export])
    AC_MSG_NOTICE([Metadata export is disabled due to lack of fixbuf >= 1.8.0])
    type_export=false
    OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"type export|"
])




dnl ----------------------------------------------------------------------
dnl Check for Spread Support
dnl ----------------------------------------------------------------------
AC_PATH_SPREAD([4.1])
if test "x$ac_cv_header_spread_sp_h" == "xyes"; then
   AC_SUBST(FIXBUF_REQ_LIBSPREAD, [1])
fi

dnl -------------------------------------------------------------------
dnl  Use the local timezone for command inputs and printing records
dnl -------------------------------------------------------------------
ENABLE_LOCALTIME=0
AC_ARG_ENABLE([localtime],
        [AS_HELP_STRING([--enable-localtime],
            [use the local timezone for command inputs and for printing records.  Default is to use UTC.  (Flows are always exported in UTC time.)])[]dnl
        ],[[
        if test "x$enableval" = "xyes"
        then
            ENABLE_LOCALTIME=1
        fi]])

AC_DEFINE_UNQUOTED([ENABLE_LOCALTIME], [$ENABLE_LOCALTIME],
     [Define to 1 to use the local timezone for command input and
     printing records.  Define to 0 to use UTC.])


dnl ----------------------------------------------------------------------
dnl Check for Unix vs. Linux privdrop (EWW EWW HACK EWW)
dnl ----------------------------------------------------------------------
if test "x$target_os" = "xlinux" -o \
        "x$target_os" = "xlinux-gnu"; then
    AC_MSG_NOTICE([Enabling Linux privilege drop hack])
    AC_DEFINE([LINUX_PRIVHACK], 1,
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
AM_MISSING_PROG(XSLTPROC, xsltproc)
INFOMODEL_AC_COLLECT_REGISTRIES([infomodel])
AC_PATH_PROG([PERL], [perl])

dnl ----------------------------------------------------------------------
dnl Lets put the configuation information into the version output for YAF
dnl ----------------------------------------------------------------------
OPTION_CONFIG_STRING=${OPTION_CONFIG_STRING}"\n"
AC_DEFINE_UNQUOTED([YAF_ACONF_STRING_STR], ["${OPTION_CONFIG_STRING}"], [configure script options])


dnl ----------------------------------------------------------------------
dnl Write Makefiles (and all the other files too)
dnl ----------------------------------------------------------------------
AC_SUBST(LIBCOMPAT)
AC_SUBST(RPM_CONFIG_FLAGS)


dnl automake 1.9 doesn't substitute these automatically, so we do it ourselves
dnl just in case
AC_SUBST([abs_top_srcdir])
AC_SUBST([abs_top_builddir])

YAF_AC_WRITE_SUMMARY

AC_CONFIG_FILES([Makefile
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
                                airframe/libairframe.spec
                                airframe/Doxyfile
                                ])


AC_OUTPUT



