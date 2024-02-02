/*
** Copyright (C) 2001-2023 by Carnegie Mellon University.
**
** @OPENSOURCE_LICENSE_START@
**
** SiLK 3.22.0
**
** Copyright 2023 Carnegie Mellon University.
**
** NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
** INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
** UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
** AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
** PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
** THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
** ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
** INFRINGEMENT.
**
** Released under a GNU GPL 2.0-style license, please see LICENSE.txt or
** contact permission@sei.cmu.edu for full terms.
**
** [DISTRIBUTION STATEMENT A] This material has been approved for public
** release and unlimited distribution.  Please see Copyright notice for
** non-US Government use and distribution.
**
** GOVERNMENT PURPOSE RIGHTS - Software and Software Documentation
**
** Contract No.: FA8702-15-D-0002
** Contractor Name: Carnegie Mellon University
** Contractor Address: 4500 Fifth Avenue, Pittsburgh, PA 15213
**
** The Government's rights to use, modify, reproduce, release, perform,
** display, or disclose this software are restricted by paragraph (b)(2) of
** the Rights in Noncommercial Computer Software and Noncommercial Computer
** Software Documentation clause contained in the above identified
** contract. No restrictions apply after the expiration date shown
** above. Any reproduction of the software or portions thereof marked with
** this legend must also reproduce the markings.
**
** Carnegie Mellon(R) and CERT(R) are registered in the U.S. Patent and
** Trademark Office by Carnegie Mellon University.
**
** This Software includes and/or makes use of Third-Party Software each
** subject to its own license.
**
** DM23-0973
**
** @OPENSOURCE_LICENSE_END@
*/
#ifndef _SILK_H
#define _SILK_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk_config.h>

#include <stddef.h>
#include <stdio.h>
#ifdef    SK_HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef    SK_HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef    SK_HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef    SK_HAVE_STRING_H
#  include <string.h>
#endif
#ifdef    SK_HAVE_STRINGS_H
#  include <strings.h>
#endif
#if defined(__cplusplus) && !defined(__STDC_FORMAT_MACROS) && !defined(PRIu32)
#define __STDC_FORMAT_MACROS
#endif
#ifdef    SK_HAVE_INTTYPES_H
#  include <inttypes.h>
#endif
#ifdef    SK_HAVE_STDINT_H
#  include <stdint.h>
#endif
#ifdef    SK_HAVE_UNISTD_H
#  include <unistd.h>
#endif

#ifdef    SK_HAVE_ASSERT_H
#  include <assert.h>
#endif
#ifdef    SK_HAVE_CTYPE_H
#  include <ctype.h>
#endif
#ifdef    SK_HAVE_ERRNO_H
#  include <errno.h>
#endif
#ifdef    SK_HAVE_FCNTL_H
#  include <fcntl.h>
#endif
#ifdef    SK_HAVE_FLOAT_H
#  include <float.h>
#endif
#ifdef    SK_HAVE_LIMITS_H
#  include <limits.h>
#endif
#ifdef    SK_HAVE_MATH_H
#  include <math.h>
#endif
#ifdef    SK_HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef    SK_HAVE_PTHREAD_H
#  include <pthread.h>
#endif
#ifdef    SK_HAVE_REGEX_H
#  include <regex.h>
#endif
#ifdef    SK_HAVE_SIGNAL_H
#  include <signal.h>
#endif
#ifdef    SK_HAVE_STDARG_H
#  include <stdarg.h>
#endif
#ifdef    SK_HAVE_SYS_SELECT_H
#  include <sys/select.h>
#endif
#ifdef    SK_HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef    SK_HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef    SK_HAVE_SYS_UN_H
#  include <sys/un.h>
#endif
#ifdef    SK_HAVE_NETINET_TCP_H
#  include <netinet/tcp.h>
#endif
#ifdef    SK_HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif

#ifdef    SK_HAVE_SYS_TIME_H
#  include <sys/time.h>
#endif
#if       SK_HAVE_TIME_H
#  include <time.h>
#endif
#ifdef    SK_HAVE_DIRENT_H
#  include <dirent.h>
#endif

#ifdef    SK_HAVE_SYS_MMAN_H
#  include <sys/mman.h>
#endif
#ifdef    SK_HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif
#ifdef    SK_HAVE_SYS_WAIT_H
#  include <sys/wait.h>
#endif
#ifdef    SK_HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif

#  define SK_ENABLE_MPI_CLUSTER 0
#  undef SK_ENABLE_MPI_SHARED_DATA
#  undef SK_ENABLE_MPI_SHARED_HOME

/* make old endian macros generate errors */
#define IS_LITTLE_ENDIAN "Change IS_LITTLE_ENDIAN " "to SK_LITTLE_ENDIAN"
#define IS_BIG_ENDIAN    "Change IS_BIG_ENDIAN "    "to SK_BIG_ENDIAN"

/* support for the SILK_CLOBBER environment variable; undefine to disable */
#define SILK_CLOBBER_ENVAR  "SILK_CLOBBER"

/* Add appropriate suffix to constants */
#if !defined(INT32_C)
/* Assume we either get them all or get none of them. */
#  define  INT8_C(v)      (v)
#  define  INT16_C(v)     (v)
#  define  INT32_C(v)     (v)

#  define UINT8_C(v)      (v ## U)
#  define UINT16_C(v)     (v ## U)
#  define UINT32_C(v)     (v ## U)

#  if (SK_SIZEOF_LONG >= 8)
#    define  INT64_C(v)   (v ## L)
#    define UINT64_C(v)   (v ## UL)
#  elif (SK_SIZEOF_UNSIGNED_LONG_LONG >= 8)
#    define  INT64_C(v)   (v ## LL)
#    define UINT64_C(v)   (v ## ULL)
#  endif
#endif


/* Maxima */
#if !defined(INT8_MAX)
#  define  INT8_MAX          127
#endif
#if !defined(UINT8_MAX)
#  define UINT8_MAX          255U
#endif
#if !defined(INT16_MAX)
#  define  INT16_MAX       32767
#endif
#if !defined(UINT16_MAX)
#  define UINT16_MAX       65535U
#endif
#if !defined(INT32_MAX)
#  define  INT32_MAX   2147483647
#endif
#if !defined(UINT32_MAX)
#  define UINT32_MAX   4294967295U
#endif
#if !defined(INT64_MAX)
#  define  INT64_MAX    INT64_C(9223372036854775807)
#endif
#if !defined(UINT64_MAX)
#  define UINT64_MAX   UINT64_C(18446744073709551615)
#endif

#if !defined(ULLONG_MAX)
#  if (SK_SIZEOF_UNSIGNED_LONG_LONG == 8)
#    define ULLONG_MAX UINT64_MAX
#  endif
#endif
#if !defined(SIZE_MAX)
#  if (SK_SIZEOF_SIZE_T >= 8)
#    define SIZE_MAX   UINT64_MAX
#  else
#    define SIZE_MAX   UINT32_MAX
#  endif
#endif
#if !defined(SSIZE_MAX)
#  if (SK_SIZEOF_SSIZE_T >= 8)
#    define SSIZE_MAX  INT64_MAX
#  else
#    define SSIZE_MAX  INT32_MAX
#  endif
#endif

/* PRI* macros for printing */
#if !defined(PRIu32)
/* Assume we either get them all or get none of them. */
#  define PRId32 "d"
#  define PRIi32 "i"
#  define PRIo32 "o"
#  define PRIu32 "u"
#  define PRIx32 "x"
#  define PRIX32 "X"

#  define PRId16 PRId32
#  define PRIi16 PRIi32
#  define PRIo16 PRIo32
#  define PRIu16 PRIu32
#  define PRIx16 PRIx32
#  define PRIX16 PRIX32

#  define PRId8  PRId32
#  define PRIi8  PRIi32
#  define PRIo8  PRIo32
#  define PRIu8  PRIu32
#  define PRIx8  PRIx32
#  define PRIX8  PRIX32
#endif /* !defined(PRIU32) */
#if !defined(PRIu64)
#  if (SK_SIZEOF_LONG >= 8)
#    define PRId64 "l" PRId32
#    define PRIi64 "l" PRIi32
#    define PRIo64 "l" PRIo32
#    define PRIu64 "l" PRIu32
#    define PRIx64 "l" PRIx32
#    define PRIX64 "l" PRIX32
#  else
#    define PRId64 "ll" PRId32
#    define PRIi64 "ll" PRIi32
#    define PRIo64 "ll" PRIo32
#    define PRIu64 "ll" PRIu32
#    define PRIx64 "ll" PRIx32
#    define PRIX64 "ll" PRIX32
#  endif
#endif /* !defined(PRIu64) */
#if !defined(PRIuMAX)
#  define PRIdMAX PRId64
#  define PRIiMAX PRIi64
#  define PRIoMAX PRIo64
#  define PRIuMAX PRIu64
#  define PRIxMAX PRIx64
#  define PRIXMAX PRIX64
#endif

/* figure out how to print size_t and ssize_t:
 * printf("%" PRIuZ "\n", SK_CAST_SIZE_T(sizeof(x))); */
#if defined(SK_HAVE_PRINTF_Z_FORMAT)
#  define SK_PRIdZ "zd"
#  define SK_PRIiZ "zi"
#  define SK_PRIoZ "zo"
#  define SK_PRIuZ "zu"
#  define SK_PRIxZ "zx"
#  define SK_PRIXZ "zX"
#  define SK_CAST_SIZE_T(scs_x)  (scs_x)
#  define SK_CAST_SSIZE_T(scs_x) (scs_x)
#elif (SK_SIZEOF_SIZE_T == SK_SIZEOF_LONG)
#  define SK_PRIdZ "ld"
#  define SK_PRIiZ "li"
#  define SK_PRIoZ "lo"
#  define SK_PRIuZ "lu"
#  define SK_PRIxZ "lx"
#  define SK_PRIXZ "lX"
#  define SK_CAST_SIZE_T(scs_x)  ((unsigned long)scs_x)
#  define SK_CAST_SSIZE_T(scs_x) ((long)scs_x)
#elif (SK_SIZEOF_SIZE_T == SK_SIZEOF_UNSIGNED_LONG_LONG)
#  define SK_PRIdZ "lld"
#  define SK_PRIiZ "lli"
#  define SK_PRIoZ "llo"
#  define SK_PRIuZ "llu"
#  define SK_PRIxZ "llx"
#  define SK_PRIXZ "llX"
#  define SK_CAST_SIZE_T(scs_x)  ((unsigned long long)scs_x)
#  define SK_CAST_SSIZE_T(scs_x) ((long long)scs_x)
#else
#  define SK_PRIdZ "d"
#  define SK_PRIiZ "i"
#  define SK_PRIoZ "o"
#  define SK_PRIuZ "u"
#  define SK_PRIxZ "x"
#  define SK_PRIXZ "X"
#  define SK_CAST_SIZE_T(scs_x)  ((unsigned int)scs_x)
#  define SK_CAST_SSIZE_T(scs_x) ((int)scs_x)
#endif


/* Functions and types from C99 that we require */
#ifndef SK_HAVE_INTMAX_T
#  define intmax_t sk_intmax_t
#endif
#ifndef SK_HAVE_IMAXDIV_T
#  define imaxdiv_t sk_imaxdiv_t
#endif
#ifndef SK_HAVE_IMAXDIV
#  define imaxdiv sk_imaxdiv
#endif
#ifndef SK_HAVE_MEMCCPY
#  define memccpy sk_memccpy
#endif
#ifndef SK_HAVE_SETENV
#  define setenv sk_setenv
#endif
#ifndef SK_HAVE_STRSEP
#  define strsep sk_strsep
#endif
#ifndef SK_HAVE_TIMEGM
#  define timegm sk_timegm
#endif


/* various IP protocols */
#ifndef IPPROTO_ICMP
#  define IPPROTO_ICMP    1
#endif
#ifndef IPPROTO_TCP
#  define IPPROTO_TCP     6
#endif
#ifndef IPPROTO_UDP
#  define IPPROTO_UDP    17
#endif
#ifndef IPPROTO_ICMPV6
#  define IPPROTO_ICMPV6 58
#endif


/*
 *    Convert a three part version number MAJOR, MINOR, PATCH to an
 *    integer.
 */
#define SK_VERS3_TO_NUMBER(m_vtn1, m_vtn2, m_vtn3)              \
    (((((m_vtn1) * 1000) + (m_vtn2)) * 1000) + (m_vtn3))

/*
 *    Compute an integer for the current gcc version.
 */
#ifndef __GNUC__
#define SK_GNUC_VERSION 0
#else
#define SK_GNUC_VERSION                                                 \
    SK_VERS3_TO_NUMBER(__GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__)
#endif

/* Wrap UNUSED() around unused parameters to silence gcc -W */
#ifndef __GNUC__
#define UNUSED(var) /*@unused@*/ var
#define NORETURN
#else
#define UNUSED(var) /*@unused@*/ var __attribute__((__unused__))
#define NORETURN  __attribute__((__noreturn__))
#endif

/*  Allow gcc to check parameters to printf-style functions and
 *  to printf-style function-pointer typedefs */
#ifndef __GNUC__
#define SK_CHECK_PRINTF(fmt_pos, argv1)
#define SK_CHECK_TYPEDEF_PRINTF(fmt_pos, argv1_pos)
#else
#define SK_CHECK_PRINTF(fmt_pos, argv1_pos)                     \
    __attribute__((format (printf, fmt_pos, argv1_pos)))
#ifndef SK_HAVE_COMP_ATTRIBUTE_PRINTF_TYPEDEF
#define SK_CHECK_TYPEDEF_PRINTF(fmt_pos, argv1_pos)
#else
#define SK_CHECK_TYPEDEF_PRINTF(fmt_pos, argv1_pos)             \
    SK_CHECK_PRINTF(fmt_pos, argv1_pos)
#endif
#endif

/*
 *  Macros to check whether the compiler supports #pragma statements
 *  for pushing and popping the state of diagnostic messages.
 */
#if defined(__clang__)
/*  Assume all versions of clang support push and pop */

#  define SK_DIAG_STR(ds_str)  #ds_str
#  define SK_DIAGNOSTIC_IGNORE_PUSH(dip_str)                    \
    _Pragma("clang diagnostic push")                            \
    _Pragma(SK_DIAG_STR(clang diagnostic ignored dip_str))
#  define SK_DIAGNOSTIC_IGNORE_POP(dip_str)     \
    _Pragma("clang diagnostic pop")

/* clang complains about non-literal format strings for functions that
 * take varargs. Disable the warnings for these functions */
#  define SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH          \
    SK_DIAGNOSTIC_IGNORE_PUSH("-Wformat-nonliteral")
#  define SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP           \
    SK_DIAGNOSTIC_IGNORE_POP("-Wformat-nonliteral")     \

#  define SK_GCC_DEPRECATED     __attribute__((__deprecated__))

#elif defined(__GNUC__)

/*
 *  '#pragma GCC diagnostic push/pop' requires gcc 4.6 or later.
 *  '#pragma GCC diagnostic warning' requires gcc 4.2.4 or later.
 *  '#pragma GCC diagnostic ignore' requires gcc 4.2 or later.
 */
#if SK_GNUC_VERSION >= SK_VERS3_TO_NUMBER(4, 6, 0)

#  define SK_DIAG_STR(ds_str)  #ds_str
#  define SK_DIAGNOSTIC_IGNORE_PUSH(dip_str)                    \
    _Pragma("GCC diagnostic push")                              \
    _Pragma(SK_DIAG_STR(GCC diagnostic ignored dip_str))
#  define SK_DIAGNOSTIC_IGNORE_POP(dip_str)     \
    _Pragma("GCC diagnostic pop")

#elif SK_GNUC_VERSION >= SK_VERS3_TO_NUMBER(4, 2, 0)

#  define SK_DIAG_STR(ds_str)  #ds_str
#  define SK_DIAGNOSTIC_IGNORE_PUSH(dip_str)                    \
    _Pragma(SK_DIAG_STR(GCC diagnostic ignored dip_str))

#if SK_GNUC_VERSION >= SK_VERS3_TO_NUMBER(4, 2, 4)
#  define SK_DIAGNOSTIC_IGNORE_POP(dip_str)                     \
    _Pragma(SK_DIAG_STR(GCC diagnostic warning dip_str))
#endif
#endif  /* GCC version for push/pop, warning, ignore */

#if SK_GNUC_VERSION >= SK_VERS3_TO_NUMBER(3, 1, 0)
#  define SK_GCC_DEPRECATED     __attribute__((__deprecated__))
#endif

#endif  /* Compiler: clang, GCC */

#ifndef SK_DIAGNOSTIC_IGNORE_PUSH
#  define SK_DIAGNOSTIC_IGNORE_PUSH(dip_str)
#endif
#ifndef SK_DIAGNOSTIC_IGNORE_POP
#  define SK_DIAGNOSTIC_IGNORE_POP(dip_str)
#endif
#ifndef SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
#  define SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH
#endif
#ifndef SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP
#  define SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP
#endif
#ifndef SK_GCC_DEPRECATED
#  define SK_GCC_DEPRECATED
#endif


/*  Alternate approach to marking unused parameters */
#define SK_UNUSED_PARAM(unused_param)   (void)(unused_param)


/*
 *  Create a variable for magic RCS variables: Define 'var' to be the
 *  string in 'id'.  Can be used in header, keep 'var's unique.  Use:
 *  RCSIDENTVAR(myheader, "$Magic RCS Var$");
 */
#ifndef SK_HAVE_COMP_ATTRIBUTE_USED
#define RCSIDENTVAR(var, id) \
    static const char /*@observer@*/ UNUSED(* var) = (id)
#else
/*
 *  Have RCSIDENTVAR() mark the variables as "used" so GCC doesn't
 *  strip them.
 */
#define RCSIDENTVAR(var, id) \
    static const char /*@observer@*/ /*@unused@*/ * var __attribute__((__used__)) = (id)
#endif /* SK_HAVE_COMP_ATTRIBUTE_USED */

/*
 *  As above, except for C files since 'var' can be fixed.
 */
#define RCSIDENT(id) RCSIDENTVAR(_rcsID, (id))


RCSIDENTVAR(rcsID_SILK_H, "$SiLK: silk.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");


/* Name of environment variable pointing to the root of install */
#define ENV_SILK_PATH "SILK_PATH"

/* First look for plugins in these sub-directories of $SILK_PATH; if
 * that fails, look for plugins in these sub-directories of the
 * binary's parent directory; if that fails, use platform's default
 * (LD_LIBRARY_PATH or similar). */
#define SILK_SUBDIR_PLUGINS                                     \
    { "lib64/silk", "lib64", "lib/silk", "lib", (char*)NULL }

/* Subdirectory of $SILK_PATH for support files */
#define SILK_SUBDIR_SUPPORT "share"


/*
 *    Functions declared in utils.h, defined in sku-app.c, that print
 *    messages to the stderr.
 */
void
skAppPrintAbortMsg(
    const char         *func_name,
    const char         *file_name,
    int                 line_number);
void
skAppPrintBadCaseMsg(
    const char         *func_name,
    const char         *file_name,
    int                 line_number,
    int64_t             value,
    const char         *value_expr);

/* include abort() in macro definition so compiler knows function exits */
#ifdef SK_HAVE_C99___FUNC__
#define skAbort()                                               \
    do {                                                        \
        skAppPrintAbortMsg(__func__, __FILE__, __LINE__);       \
        abort();                                                \
    } while(0)
#define skAbortBadCase(abc_expr)                                \
    do {                                                        \
        skAppPrintBadCaseMsg(__func__, __FILE__, __LINE__,      \
                             (int64_t)(abc_expr), #abc_expr);   \
        abort();                                                \
    } while(0)
#else
#define skAbort()                                       \
    do {                                                \
        skAppPrintAbortMsg(NULL, __FILE__, __LINE__);   \
        abort();                                        \
    } while(0)
#define skAbortBadCase(abc_expr)                                \
    do {                                                        \
        skAppPrintBadCaseMsg(NULL, __FILE__, __LINE__,          \
                             (int64_t)(abc_expr), #abc_expr);   \
        abort();                                                \
    } while(0)
#endif


/* Bit-swapping macros for changing endianness */
#if  SK_LITTLE_ENDIAN
#  define  BSWAP16(a)  (ntohs(a))
#  define  BSWAP32(a)  (ntohl(a))
#else
#  define BSWAP16(a) ((((uint16_t)(a)) >> 8) |    \
                      (((uint16_t)(a)) << 8))
#  define BSWAP32(a) (((((uint32_t)(a)) & 0x000000FF) << 24) |    \
                      ((((uint32_t)(a)) & 0x0000FF00) << 8)  |    \
                      ((((uint32_t)(a)) & 0x00FF0000) >> 8)  |    \
                      ((((uint32_t)(a)) >> 24) & 0x000000FF))
#endif /* SK_LITTLE_ENDIAN */
#define BSWAP64(a)                                              \
    ((((uint64_t)BSWAP32((uint32_t)((a) & 0xffffffff))) << 32)  \
     | BSWAP32((uint32_t)((a) >> 32)))


/* provide a network-to-host swapper for 64bit values */
#if   SK_LITTLE_ENDIAN
#  define ntoh64(a)  BSWAP64(a)
#else
#  define ntoh64(a)  (a)
#endif
#define hton64(a)  ntoh64(a)

#ifdef __cplusplus
}
#endif
#endif /* _SILK_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
