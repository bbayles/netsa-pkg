dnl Process this file with autoconf to produce a configure script
dnl ------------------------------------------------------------------------
dnl yafconfig.m4
dnl write summary of configure to a file (stolen from SiLK)
dnl ------------------------------------------------------------------------
dnl Copyright (C) 2013-2023 Carnegie Mellon University. All Rights Reserved.
dnl ------------------------------------------------------------------------
dnl Authors: Emily Sarneso
dnl ------------------------------------------------------------------------
dnl GNU General Public License (GPL) Rights pursuant to Version 2, June 1991
dnl Government Purpose License Rights (GPLR) pursuant to DFARS 252.227-7013
dnl ------------------------------------------------------------------------

AC_DEFUN([YAF_AC_WRITE_SUMMARY],[
    AC_SUBST(YAF_SUMMARY_FILE)
    YAF_SUMMARY_FILE=yaf-summary.txt

    YF_FINAL_MSG="
    * Configured package:           ${PACKAGE_STRING}
    * pkg-config path:              ${PKG_CONFIG_PATH}
    * Host type:                    ${build}
    * OS:                           $target_os
    * Source files (\$top_srcdir):   $srcdir
    * Install directory:            $prefix"


    YF_LIBSTR_STRIP($GLIB_LIBS)
    YF_FINAL_MSG="$YF_FINAL_MSG
    * GLIB:                         $yf_libstr"

    if test "x$ENABLE_LOCALTIME" = "x1"
    then
        YF_BUILD_CONF="
    * Timezone support:             local"
    else
        YF_BUILD_CONF="
    * Timezone support:             UTC"
    fi

    YF_PKGCONFIG_VERSION(libfixbuf)
    YF_PKGCONFIG_LPATH(libfixbuf)
    yf_msg_ldflags=`echo "$yfpkg_lpath" | sed 's/^ *//' | sed 's/ *$//'`
    YF_BUILD_CONF="$YF_BUILD_CONF
    * Libfixbuf version:            ${yfpkg_ver}"

    if test "x$pcap_from" != "x"
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Libpcap from:                 ${pcap_from}"
    fi

    if test "x$dagapi" = xtrue
    then
       yf_msg_ldflags=`echo "$DAG_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//'`
       YF_BUILD_CONF="$YF_BUILD_CONF
    * DAG support:                  YES $yf_msg_ldflags"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * DAG support:                  NO"
    fi

    if test "x$napapi" = xtrue
    then
       yf_msg_ldflags=`echo "NAPA_LDFLAGS" | sed 's/^ *//' | sed 's/ *$//'`
       YF_BUILD_CONF="$YF_BUILD_CONF
    * NAPATECH support:             YES $yf_msg_ldflags"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * NAPATECH support:             NO"
    fi

    if test "x$pfring" = xtrue
    then
       if test "x$pfringzc" = xtrue
       then
          YF_BUILD_CONF="$YF_BUILD_CONF
    * PFRING support:               YES (ZC)"
       else
          YF_BUILD_CONF="$YF_BUILD_CONF
    * PFRING support:               YES (NO ZC)"
       fi
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * PFRING support:               NO"
    fi

    if test "x$nfeapi" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * NETRONOME support:            YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * NETRONOME support:            NO"
    fi

    if test "x$biviozcopy" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * BIVIO support:                YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * BIVIO support:                NO"
    fi


    if test "x$compact_v4" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Compact IPv4 support:         YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Compact IPv4 support:         NO"
    fi

    if test "x$plugins" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Plugin support:               YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Plugin support:               NO"
    fi

    if test "x$pcreexist" = xtrue
    then
       YF_PKGCONFIG_LPATH(libpcre)
       yf_msg_ldflags=`echo "$yfpkg_lpath" | sed 's/^ *//' | sed 's/ *$//'`
       YF_BUILD_CONF="$YF_BUILD_CONF
    * PCRE support:                 YES ${yf_msg_ldflags}"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * PCRE support:                 NO"
    fi

    if test "x$applabeler" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Application Labeling:         YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Application Labeling:         NO"
    fi

    if test "x$ndpi" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * nDPI Support:                 YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * nDPI Support:                 NO"
    fi

    if test "x$exportDNSAuth" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * DNS Authoritative Response Only:  ON"
    fi

    if test "x$exportDNSNXDomain" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * DNS NXDomain Only:            ON"
    fi

    if test "x$nopayload" = xfalse
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Payload Processing Support:   YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Payload Processing Support:   NO"
    fi

    if test "x$entropycalc" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Entropy Support:              YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Entropy Support:              NO"
    fi

    if test "x$daginterfacehack" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Interface recording:          YES(dag)"
    elif test "x$interface" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Interface recording:          YES"
    fi

    if test "x$fp_exporter" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Fingerprint Export Support:   YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Fingerprint Export Support:   NO"
    fi

    if test "x$p0f_printer" = xtrue
    then
      YF_PKGCONFIG_LPATH(libp0f)
      YF_BUILD_CONF="$YF_BUILD_CONF
    * P0F Support:                  YES ${yfpkg_lpath}"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * P0F Support:                  NO"
    fi

    if test "x$mpls" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * MPLS NetFlow Enabled:         YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * MPLS NetFlow Enabled:         NO"
    fi

    if test "x$nonip" = xtrue
    then
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Non-IP Flow Enabled:          YES"
    else
       YF_BUILD_CONF="$YF_BUILD_CONF
    * Non-IP Flow Enabled:          NO"
    fi

    yfpkg_spread=`$PKG_CONFIG --cflags libfixbuf | grep 'SPREAD'`
    if test "x$yfpkg_spread" = "x"
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Spread Support:               NO"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Spread Support:               YES"
    fi

    if test "x$type_export" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Type export Support:          YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Type export Support:          NO"
    fi

    if test "x$gcc_atomic" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * GCC Atomic Builtin functions: YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * GCC Atomic Builtin functions: NO"
    fi

    if test "x$type_export" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * IE metadata export available: YES"
    else
      YF_BUILD_CONF="$YF_BUILD_CONF
    * IE metadata export available: NO"
    fi

    if test "x$disable_mt" = xtrue
    then
      YF_BUILD_CONF="$YF_BUILD_CONF
    * Multi-threading available:    NO (reconfigure with --without-pic)"
    fi

    # Remove leading whitespace
    yf_msg_cflags="$CPPFLAGS $CFLAGS"
    yf_msg_cflags=`echo "$yf_msg_cflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_ldflags="$YF_LDFLAGS $LDFLAGS"
    yf_msg_ldflags=`echo "$yf_msg_ldflags" | sed 's/^ *//' | sed 's/  */ /g'`

    yf_msg_libs="$LIBS"
    yf_msg_libs=`echo "$yf_msg_libs" | sed 's/^ *//' | sed 's/  */ /g'`

    YF_FINAL_MSG="$YF_FINAL_MSG $YF_BUILD_CONF
    * Compiler (CC):                $CC
    * Compiler flags (CFLAGS):      $yf_msg_cflags
    * Linker flags (LDFLAGS):       $yf_msg_ldflags
    * Libraries (LIBS):             $yf_msg_libs
"

    echo "$YF_FINAL_MSG" > $YAF_SUMMARY_FILE

    AC_CONFIG_COMMANDS([yaf_summary],[
        if test -f $YAF_SUMMARY_FILE
        then
            cat $YAF_SUMMARY_FILE
        fi],[YAF_SUMMARY_FILE=$YAF_SUMMARY_FILE])

    # Put YAF_SUMMARY_FILE into the environment so that the Lua
    # subpackage can output it.
    YAF_SUMMARY_FILE=`pwd`"/${YAF_SUMMARY_FILE}"
    export YAF_SUMMARY_FILE

  #Put config info into the version output of yaf
  YF_BUILD_CONF=${YF_BUILD_CONF}"\n"
  #AC_DEFINE_UNQUOTED([YAF_BCONF_STRING_STR], ["${YF_BUILD_CONF}"], [configure script options])
])
