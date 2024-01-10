/*
** Copyright (C) 2004-2023 by Carnegie Mellon University.
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
#ifndef _SKSTREAM_PRIV_H
#define _SKSTREAM_PRIV_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKSTREAM_PRIV_H, "$SiLK: skstream_priv.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  skstream_priv.h
**
**  For sharing of functions to read/write SiLK Flow records
**
**  THESE FUNCTIONS ARE FOR INTERNAL USE BY skStream*().
**
*/

#include <silk/skstream.h>
#include <silk/rwrec.h>
#include <silk/sksite.h>
#include <silk/utils.h>
#include "skiobuf.h"


/* macros to swap the bytes in place */
#define SWAP_DATA64(d) *((uint64_t*)(d)) = BSWAP64(*(uint64_t*)(d))
#define SWAP_DATA32(d) *((uint32_t*)(d)) = BSWAP32(*(uint32_t*)(d))
#define SWAP_DATA16(d) *((uint16_t*)(d)) = BSWAP16(*(uint16_t*)(d))
#if 0
/* macros to swap the bytes in place */
#define _SWAP_HELP(_byte, ar, a, b)             \
    {                                           \
        (_byte) = (ar)[(a)];                    \
        (ar)[(a)] = (ar)[(b)];                  \
        (ar)[(b)] = (_byte);                    \
    }
#define SWAP_DATA16(ar)                         \
    {                                           \
        uint8_t _byte;                          \
        _SWAP_HELP(_byte, (ar), 0, 1);          \
    }
#define SWAP_DATA32(ar)                         \
    {                                           \
        uint8_t _byte;                          \
        _SWAP_HELP(_byte, (ar), 0, 3);          \
        _SWAP_HELP(_byte, (ar), 1, 2);          \
    }
#define SWAP_DATA64(ar)                         \
    {                                           \
        uint8_t _byte;                          \
        _SWAP_HELP(_byte, (ar), 0, 7);          \
        _SWAP_HELP(_byte, (ar), 1, 6);          \
        _SWAP_HELP(_byte, (ar), 2, 5);          \
        _SWAP_HELP(_byte, (ar), 3, 4);          \
    }
#endif /* 0 */


/*
 *    We store the packet count in a 20 bit value.  When the packet
 *    count is larger than that, we divide the value by the
 *    PKTS_DIVISOR and store the result.  That gives an absolute max
 *    of 67,100,864 packets.
 */
#define MAX_PKTS              1048576   /* 2^20 */
#define PKTS_DIVISOR               64
#define DBL_MAX_PKTS         67108864   /* 2^26 */

#define BPP_BITS                    6
#define BPP_PRECN                  64   /* 2^BPP_BITS */
#define BPP_PRECN_DIV_2            32   /* 2^BPP_BITS/2 */


/*
 *    We pack flows by their start time into hourly files.  The file's
 *    hour is stored in the header; each record's start time is offset
 *    from that and stored in 12 bits.
 */
#define MAX_START_TIME           4096   /* 2^12 */

/*
 *    The elapsed time is the offset from the record's start time.  We
 *    assume the router flushes flows at least once an hour, though in
 *    practice CISCO flushes every 30 mintues.  The elapsed time is
 *    stored in 11 or 12 bits, depending on file format.
 */
#define MAX_ELAPSED_TIME         4096   /* 2^12 */
#define MAX_ELAPSED_TIME_OLD     2048   /* 2^11 */


/*
 *    Masks for bit field manipulation: these masks will pass the
 *    specified number of bits strarting from the least significant
 *    bit.  For example, masking a value with MASKARRAY_01 gives the
 *    least significant bit; MASKARRAY_09 gives the rightmost 9 bits,
 *    etc.
 */
#define MASKARRAY_01    1U
#define MASKARRAY_02    3U
#define MASKARRAY_03    7U
#define MASKARRAY_04    15U
#define MASKARRAY_05    31U
#define MASKARRAY_06    63U
#define MASKARRAY_07    127U
#define MASKARRAY_08    255U

#define MASKARRAY_09    511U
#define MASKARRAY_10    1023U
#define MASKARRAY_11    2047U
#define MASKARRAY_12    4095U
#define MASKARRAY_13    8191U
#define MASKARRAY_14    16383U
#define MASKARRAY_15    32767U
#define MASKARRAY_16    65535U

#define MASKARRAY_17    131071U
#define MASKARRAY_18    262143U
#define MASKARRAY_19    524287U
#define MASKARRAY_20    1048575U
#define MASKARRAY_21    2097151U
#define MASKARRAY_22    4194303U
#define MASKARRAY_23    8388607U
#define MASKARRAY_24    16777215U

#define MASKARRAY_25    33554431U
#define MASKARRAY_26    67108863U
#define MASKARRAY_27    134217727U
#define MASKARRAY_28    268435455U
#define MASKARRAY_29    536870911U
#define MASKARRAY_30    1073741823U
#define MASKARRAY_31    2147483647U


/* Web classification utilities */

/* SK_WEBPORT_CHECK(p) is defined in rwrec.h */

/*
 *  encoding = SK_WEBPORT_ENCODE(p)
 *
 *    Encode the port 'p' into a value suitable for storing in the
 *    wPort field of an FT_RWWWW record.
 */
#define SK_WEBPORT_ENCODE(p)                    \
    (((p) == 80)                                \
     ? 0                                        \
     : (((p) == 443)                            \
        ? 1u                                    \
        : (((p) == 8080)                        \
           ? 2u                                 \
           : 3u)))


/*
 *  decoding = SK_WEBPORT_EXPAND(p)
 *
 *    Decode the port 'p' from the value stored in the wPort field in
 *    an FT_RWWWW record.
 */
#define SK_WEBPORT_EXPAND(p)                            \
    (((p) == 0)                                         \
     ? 80                                               \
     : (((p) == 1)                                      \
        ? 443                                           \
        : (((p) == 2)                                   \
           ? 8080                                       \
           : 0)))


/*
 *    Unless the SK_NOTFIX_TCPSTATE_EXPANDED cpp macro is defined, fix
 *    records that were written prior to SiLK-3.6.0 on read.
 *
 *    These broken records have the SK_TCPSTATE_EXPANDED bit set on
 *    either non-TCP records or on records where the initial-tcpflags
 *    and session-tcpflags values are both 0.
 */
#ifdef SK_NOTFIX_TCPSTATE_EXPANDED
#  define RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(r)
#else
#  define RWREC_MAYBE_CLEAR_TCPSTATE_EXPANDED(r)                            \
    if (rwRecGetTcpState(r) & SK_TCPSTATE_EXPANDED                          \
        && (IPPROTO_TCP != rwRecGetProto(r)                                 \
            || (0 == rwRecGetInitFlags(r) && 0 == rwRecGetRestFlags(r))))   \
    {                                                                       \
        rwRecSetTcpState(r, (rwRecGetTcpState(r) & ~SK_TCPSTATE_EXPANDED)); \
        rwRecSetInitFlags(r, 0);                                            \
        rwRecSetRestFlags(r, 0);                                            \
    }
#endif  /* SK_NO_TCP_STATE_FIX */

/* Formerly public macros only used by flowcapio.c and rwfilterio.c */

/*
 *    Return only the milliseconds portion of an rwRec's start time.
 */
#define rwRecGetStartMSec(r)    ((uint16_t)(rwRecGetStartTime(r) % 1000))

/*
 *    Return only the milliseconds portion of an rwRec's elapsed
 *    field.
 */
#define rwRecGetElapsedMSec(r)  ((uint16_t)(rwRecGetElapsed(r) % 1000))




struct skstream_st {
    /* A FILE pointer to the file */
    FILE                   *fp;
#if SK_ENABLE_ZLIB
    /* When the entire file has been compressed, we use gzread/gzwrite
     * to process the file, this is interface to those functions */
    gzFile                  gz;
#endif

    /* A handle to our own I/O buffering code */
    sk_iobuf_t             *iobuf;

    /* The full path to the file */
    char                   *pathname;

    /* For a SiLK file, this holds the file's header */
    sk_file_header_t       *silk_hdr;

    /* Number of records read or written.  For appending, this is the
     * number records added to the file. */
    uint64_t                rec_count;

    /* Start time as recorded in file's header, or 0. For easy access */
    sktime_t                hdr_starttime;

    /* Pointer to a function to convert an array of bytes into a record */
    int                   (*rwUnpackFn)(skstream_t*, rwRec*, uint8_t*);
    /* Pointer to a function to convert a record into an array of bytes */
    int                   (*rwPackFn)(skstream_t*, const rwRec*, uint8_t*);
    /* The stream to copy the input to---for support of the --all-dest
     * and --copy-input switches */
    skstream_t             *copyInputFD;

    /* An object to hold the parameter that caused the last error */
    union {
        uint32_t        num;
        const rwRec    *rec;
    }                       errobj;

    /* Offset where the skIOBuf was created */
    off_t                   pre_iobuf_pos;

    /* Return value from most recent function skStream* call.  See
     * also err_info.  Should we combine these into a single value? */
    ssize_t                 last_rv;

    /* Holds the most recent error code.  See also last_rv.  Should we
     * combine these into a single value? */
    int                     err_info;

    /* The errno from the last system call that failed */
    int                     errnum;

    /* The open file descriptor, or -1 if closed */
    int                     fd;

    /* The fixed length of records of this type */
    uint16_t                recLen;

    /* The sensor ID stored in the file's header, or
     * SK_INVALID_SENSOR.  For easy access. */
    sk_sensor_id_t          hdr_sensor;

    /* The flowtype ID stored in the file's header, or
     * SK_INVALID_FLOWTYPE.  For easy access. */
    sk_flowtype_id_t        hdr_flowtype;

    /* Whether stream is read, write, append. */
    skstream_mode_t         io_mode;

    /* ipv6 policy */
    sk_ipv6policy_t         v6policy;

    /* When sending textual output to a pager, the name of the pager
     * to use */
    char                   *pager;

    /* When reading textual input, the text that denotes the start of
     * a comment. */
    char                   *comment_start;

    /* The type of data to read/write: text, silk, silk-flow, etc */
    skcontent_t             content_type;

    /* Set to 1 if the stream is seekable (i.e., a "real" file) */
    unsigned                is_seekable     :1;

    /* Set to 1 if the stream is a binary stream with a SiLK header */
    unsigned                is_silk         :1;

    /* Set to 1 if the stream contains SiLK flow data */
    unsigned                is_silk_flow    :1;

    /* Set to 1 if the pager is being used for textual output. */
    unsigned                is_pager_active :1;

    /* Set to 1 if the stream contains binary data (silk or non-silk) */
    unsigned                is_binary       :1;

    /* Set to 1 if the stream is connected to a terminal (tty) */
    unsigned                is_terminal     :1;

    /* Set to 1 if data has been read-from/written-to the stream */
    unsigned                is_dirty        :1;

    /* Set to 1 if the stream has been closed */
    unsigned                is_closed       :1;

    /* Set to 1 if the stream is coming from an MPI node */
    unsigned                is_mpi          :1;

    /* Set to 1 if the stream is connected to a standard I/O stream */
    unsigned                is_stdio        :1;

    /* Set to 1 if the stream is not using the IOBuf */
    unsigned                is_unbuffered   :1;

    /* Set to 1 if the stream has reached the end-of-file. */
    unsigned                is_eof          :1;

    /* Set to 1 if an error has occurred in an skStream* function that
     * was called by an skIOBuf* function as part of a callback */
    unsigned                is_iobuf_error  :1;

    /* Set to 1 if the silk flow data in this stream supports IPv6 */
    unsigned                supports_ipv6   :1;

    /* Set to 1 if the silk header has been read from the stream */
    unsigned                have_hdr        :1;

    /* Set to 1 if the data in the stream is in non-native byte order */
    unsigned                swapFlag        :1;
};
/* skstream_t */



/*  *****  Functions exported from each rw<format>io.c file  *****  */


/*
 *  status = <format>ioPrepare(stream);
 *
 *    DO NOT CALL DIRECTLY.  FOR INTERNAL LIBRW USE
 *
 *    Sets the record version to the default if it is unspecified,
 *    checks that the record format supports the requested record
 *    version, sets the record length, and sets the pack and unpack
 *    functions for this record format and version.
 *
 *    Returns SKSTREAM_OK on success; otherwise returns an error code
 *    on failure: bad version.
 */
int
augmentedioPrepare(
    skstream_t         *stream);
int
augroutingioPrepare(
    skstream_t         *stream);
int
augsnmpoutioPrepare(
    skstream_t         *stream);
int
augwebioPrepare(
    skstream_t         *stream);
int
filterioPrepare(
    skstream_t         *stream);
int
flowcapioPrepare(
    skstream_t         *stream);
int
genericioPrepare(
    skstream_t         *stream);
int
ipv6ioPrepare(
    skstream_t         *stream);
int
ipv6routingioPrepare(
    skstream_t         *stream);
int
notroutedioPrepare(
    skstream_t         *stream);
int
routedioPrepare(
    skstream_t         *stream);
int
splitioPrepare(
    skstream_t         *stream);
int
wwwioPrepare(
    skstream_t         *stream);


/*
 *  length = <format>ioGetRecLen(version);
 *
 *    Return the on-disk length in bytes of records of the specified
 *    type and vresion; or return 0 if the specified version is not
 *    defined for the given type.
 */
uint16_t
augmentedioGetRecLen(
    sk_file_version_t);
uint16_t
augroutingioGetRecLen(
    sk_file_version_t);
uint16_t
augsnmpoutioGetRecLen(
    sk_file_version_t);
uint16_t
augwebioGetRecLen(
    sk_file_version_t);
uint16_t
filterioGetRecLen(
    sk_file_version_t);
uint16_t
flowcapioGetRecLen(
    sk_file_version_t);
uint16_t
genericioGetRecLen(
    sk_file_version_t);
uint16_t
ipv6ioGetRecLen(
    sk_file_version_t);
uint16_t
ipv6routingioGetRecLen(
    sk_file_version_t);
uint16_t
notroutedioGetRecLen(
    sk_file_version_t);
uint16_t
routedioGetRecLen(
    sk_file_version_t);
uint16_t
splitioGetRecLen(
    sk_file_version_t);
uint16_t
wwwioGetRecLen(
    sk_file_version_t);



/*  *****  rwpack.c  *****  */

#ifdef RWPACK_BYTES_PACKETS
/*
 *    Uses fields from the rwRec pointed to by 'rwrec' to compute the
 *    bytes-per-packet ('bpp'), packets ('pkts'), and
 *    packets-multiplier ('pflag') field required by the packed file
 *    formats FILTER, SPLIT, WWW, ROUTED, and NOTROUTED.
 *
 *    The parameters 'bpp', 'pkts', and 'pflag' will be the values to
 *    store in the packed file format; i.e., they will be the values
 *    that rwpackUnpackBytesPackets() can read; they will be in native
 *    byte order.
 *
 *    Specifically, 'pkts' is either the packet count or the packet
 *    count divided by the PKTS_DIVISOR when 'pflag' is non-zero.
 *    'bpp' is the bytes-per-packet ratio given by a 14 bit value and
 *    a 6 bit fractional part.
 *
 *    This function returns SKSTREAM_OK on success, or the following
 *    to indicate an error: SKSTREAM_ERR_PKTS_ZERO-the 'pkts' field on
 *    rwrec is 0; SKSTREAM_ERR_PKTS_OVRFLO-the 'pkts' value is too
 *    large to store in the packed file format.
 */
static int
rwpackPackBytesPackets(
    uint32_t               *bpp_out,
    uint32_t               *pkts_out,
    uint32_t               *pflag_out,
    const rwGenericRec_V5  *rwrec);


/*
 *    Does the reverse of rwpackPackBytesPackets(): Fills in the
 *    'bytes', 'packets', and 'bpp' fields of the rwRec pointed to by
 *    'rwrec'.  All values are expected to be in native byte order.
 *
 *    This function does no error checking.
 */
static void
rwpackUnpackBytesPackets(
    rwGenericRec_V5    *rwrec,
    uint32_t            bpp,
    uint32_t            pkts,
    uint32_t            pflag);
#endif  /* RWPACK_BYTES_PACKETS */


#ifdef RWPACK_PROTO_FLAGS
/*
 *    Uses fields from the rwRec pointed to by 'rwrec' to compute the
 *    values pointed to by these variables:
 *
 *        is_tcp_out - 1 if the flow is TCP (proto==6); 0 otherwise
 *
 *        prot_flags_out - protocol when is_tcp==0; bitwise OR of TCP
 *        flags on ALL packages when is_tcp==1 and tcp_state!=0; TCP
 *        flags on FIRST packet when is_tcp==1 and tcp_state!=0
 *
 *        tcp_state_out - value of tcp_state field on the rwrec
 *
 *        rest_flags_out - the flags reported by the flow collector
 *        when is_tcp==0 (even though there are no flags to report);
 *        empty when is_tcp==1 and tcp_state==0; bitwise OR of TCP
 *        flags on all but the first packet when is_tcp==1 and
 *        tcp_state!=0.
 *
 *    The output variables prot_flags, tcp_state, and rest_flags will
 *    be the values to store in the packed file format; is_tcp can be
 *    stored in a single bit.  The values can be read by the
 *    rwpackUnpackProtoFlags() function.
 *
 *    This function should never fail, and thus has no return value.
 */
static void
rwpackPackProtoFlags(
    uint8_t                *is_tcp_out,
    uint8_t                *prot_flags_out,
    uint8_t                *tcp_state_out,
    uint8_t                *rest_flags_out,
    const rwGenericRec_V5  *rwrec);


/*
 *    Does the reverse of rwpackPackProtoFlags(): Fills in the 'proto',
 *    'flags', 'init_flags', 'rest_flags', and 'tcp_state' fields on
 *    the rwRec pointed to by 'rwrec'.  All values are expected to be
 *    in native byte order.
 *
 *    This function does no error checking.
 */
static void
rwpackUnpackProtoFlags(
    rwGenericRec_V5    *rwrec,
    uint8_t             is_tcp,
    uint8_t             prot_flags,
    uint8_t             tcp_state,
    uint8_t             rest_flags);
#endif  /* RWPACK_PROTO_FLAGS */


#ifdef RWPACK_SBB_PEF
/*
 *    Uses fields from the rwRec pointed to by 'rwrec' to compute the
 *    'sbb' and 'pef' fields used when packing SPLIT, WWW, ROUTED, and
 *    NOTROUTED V1 and V2 files.  'file_start_time' is the time value
 *    stored in the header--record times are offset from that time.
 *
 *    Uses the sTime, elapsed, pkts, bytes in the rwrec to compute
 *    these values.  Any millisec values for sTime and/or elapsed on
 *    the rwRec are ignored.
 *
 *    sbb and pef are returned in native byte order.
 *
 *    Returns 0 on success or non-zero on these failures: rwrec's sTime
 *    is earlier than the 'file_start_time' or is too large; elapsed
 *    time is too large; packets field is zero or too large.
 */
static int
rwpackPackSbbPef(
    uint32_t               *sbb_out,
    uint32_t               *pef_out,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time);


/*
 *    Does the reverse of rwpackPackSbbPef(): Fills in the 'sTime',
 *    'elapsed', 'bytes', 'pkts', and 'bpp' fields on the rwRec
 *    pointed to by 'rwrec'.  All values are expected to be in native
 *    byte order.
 *
 *    This function does no error checking.
 */
static void
rwpackUnpackSbbPef(
    rwGenericRec_V5    *rwrec,
    sktime_t            file_start_time,
    const uint32_t     *sbb,
    const uint32_t     *pef);
#endif  /* RWPACK_SBB_PEF */


#ifdef RWPACK_TIME_BYTES_PKTS_FLAGS
/*
 *    Computes the 'pkts_stime', 'bbe', and 'msec_flags' fields used
 *    when packing into various formats.
 *
 *    Uses the sTime, elapsed, pkts, and bytes fields in the rwRec
 *    pointed to by rwrec to compute these values.  'file_start_time'
 *    is the hour stored in the file's header---record times are
 *    offset from it.
 *
 *    sbb and pef are returned in native byte order.
 *
 *    Returns 0 on success or non-zero on these failures: rwrec's sTime
 *    is earlier than stream's sTime or is too large; elapsed time
 *    is too large; packets field is too large.
 */
static int
rwpackPackTimeBytesPktsFlags(
    uint32_t               *pkts_stime_out,
    uint32_t               *bbe_out,
    uint32_t               *msec_flags_out,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time);


/*
 *    Does the reverse of rwpackPackSbbPef(): Fills in the 'sTime',
 *    'elapsed', 'sTime_msec, 'elapsed_msec', 'bytes', 'pkts', and
 *    'bpp' fields on the rwRec pointed to by 'rwrec'.  All values are
 *    expected to be in native byte order.
 *
 *    This function does no error checking.
 */
static void
rwpackUnpackTimeBytesPktsFlags(
    rwGenericRec_V5    *rwrec,
    sktime_t            file_start_time,
    const uint32_t     *pkts_stime,
    const uint32_t     *bbe,
    const uint32_t     *msec_flags);
#endif  /* RWPACK_TIME_BYTES_PKTS_FLAGS */


#ifdef RWPACK_FLAGS_TIMES_VOLUMES
static int
rwpackPackFlagsTimesVolumes(
    uint8_t                *ar,
    const rwGenericRec_V5  *rwrec,
    sktime_t                file_start_time,
    size_t                  len);


static void
rwpackUnpackFlagsTimesVolumes(
    rwGenericRec_V5    *rwrec,
    const uint8_t      *ar,
    sktime_t            file_start_time,
    size_t              len,
    int                 is_tcp);
#endif  /* RWPACK_FLAGS_TIMES_VOLUMES */


#ifdef RWPACK_TIMES_FLAGS_PROTO
static int
rwpackPackTimesFlagsProto(
    const rwGenericRec_V5  *rwrec,
    uint8_t                *ar,
    sktime_t                file_start_time);


static void
rwpackUnpackTimesFlagsProto(
    rwGenericRec_V5    *rwrec,
    const uint8_t      *ar,
    sktime_t            file_start_time);
#endif  /* RWPACK_TIMES_FLAGS_PROTO */


#ifdef __cplusplus
}
#endif
#endif /* _SKSTREAM_PRIV_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
