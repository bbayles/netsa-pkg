dnl -*- mode: autoconf -*-
dnl Copyright 2008-2023 Carnegie Mellon University
dnl See license information in LICENSE.txt.

dnl Synopsys
dnl     Utility configuration checks for YAF.
dnl
dnl Description
dnl	Some more portability tests for running YAF on different platforms.
dnl
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
dnl
dnl Developed as part of the YAF suite, CMU SEI CERT program, Network
dnl Situational Awareness group.
dnl http://www.cert.org
dnl
dnl mailto:netsa-help@cert.org


# YF_SIZE_T_FORMAT
#
# This tests the size of size_t and creates some handy macros
# for outputting the value of size_t variables without warnings
# across platforms
#
# creates #defines:
#   SIZE_T_FORMAT regular (f)print format for unsigned value
#   SIZE_T_FORMATX regular (f)print format for value in hex
#	SIZE_T_CAST a cast to be able to cast size_t's into a standard
#               formatter type (uint??_t) that is the same size as
#               a size_t
#
AC_DEFUN([YF_SIZE_T_FORMAT],[
	
	AC_MSG_CHECKING([for size of size_t])
	
	for bitSize in "8" "16" "32" "64"
	do
		AC_RUN_IFELSE([
			AC_LANG_PROGRAM([
				#if HAVE_STDDEF_H
				#include <stddef.h>
				#endif
				#if HAVE_LIMITS_H
				#include <limits.h>
				#endif
			],[
				if (sizeof(size_t)*CHAR_BIT == $bitSize) return 0;
				return 1;
			])
		],[SIZE_T_SIZE=$bitSize])
	done

	AC_MSG_RESULT([$SIZE_T_SIZE])

	case $SIZE_T_SIZE in
		8 )
			AC_DEFINE([SIZE_T_FORMAT],[PRIu8],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_FORMATX],[PRIx8],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_CAST],[uint8_t],[size_t cast for string formatting])
			;;
		16 )
			AC_DEFINE([SIZE_T_FORMAT],[PRIu16],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_FORMATX],[PRIx16],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_CAST],[uint16_t],[size_t cast for string formatting])
			;;
		32 )
			AC_DEFINE([SIZE_T_FORMAT],[PRIu32],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_FORMATX],[PRIx32],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_CAST],[uint32_t],[size_t cast for string formatting])
			;;
		64 )
			AC_DEFINE([SIZE_T_FORMAT],[PRIu64],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_FORMATX],[PRIx64],[(f)printf format string for type size_t])
			AC_DEFINE([SIZE_T_CAST],[uint64_t],[size_t cast for string formatting])
			;;
	esac
	
])

#
# YF_PKGCONFIG_VERSION
#
# This returns the version number of the tool found for the provided
# library.  
#
# YF_PKGCONFIG_VERSION(library)
# output in yfpkg_ver
#
AC_DEFUN([YF_PKGCONFIG_VERSION],[
	AC_REQUIRE([PKG_PROG_PKG_CONFIG])
	yfpkg_ver=`$PKG_CONFIG --modversion $1`
])

#
# YF_PKGCONFIG_LPATH
#
# This returns the library path (or at least the first one returned from
# pkg-config) for the provided library.
#
#
# YF_PKGCONFIG_LPATH(library)
# output in yfpkg_lpath
#
AC_DEFUN([YF_PKGCONFIG_LPATH],[
	AC_REQUIRE([PKG_PROG_PKG_CONFIG])
	yfpkg_lpath=`$PKG_CONFIG --libs-only-L $1 | cut -d' ' -f 1`
])


#
# YF_LIBSTR_STRIP
#
# strips a gcc/ld switch string string from something like
# "-L/usr/local/foo/lib/ -lblah" to just capture the first
# path "/usr/local/foo/lib" assuming the string is formatted
# just like shown
#
# FIXME
#
# YF_LIBSTR_STRIP("ld_option_string")
# output in yf_libstr
#
AC_DEFUN([YF_LIBSTR_STRIP],[
#	_resultString=[`echo $1 | sed 's/-L\([^ ]*\).*/\1/pg'`]
#	yf_libstr=${_resultString}
	yf_libstr=$1
])

