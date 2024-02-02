/*
** Copyright (C) 2005-2023 by Carnegie Mellon University.
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

/*
**  Functions to print error message for skstream
**
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skstream-err.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include "skstream_priv.h"


/*
 *    Typedef for a printf-type function, except this function has a
 *    context object as the first parameter.
 */
typedef int (*msg_fn_with_context)(
    void       *ctxobj,
    const char *fmt,
    ...)
    SK_CHECK_TYPEDEF_PRINTF(2, 3);


/*
 *    A structure to hold a buffer and the size of the buffer.  This
 *    will be used at the context object for msg_fn_with_context.
 */
typedef struct stream_err_msg_buf_st {
    char       *buf;
    size_t      len;
} stream_err_msg_buf_t;


/*
 *    The function which looks up the current error code of the stream
 *    and calls one of two possible functions to "print" the error
 *    message.
 *
 *    This is a helper function for the two public functions,
 *    skStreamPrintLastErr() and skStreamLastErrMessage().
 *
 *    The 'errfn1' callback is used if it is set.  Otherwise, the
 *    'errfn2' function is called if it is set with 'errfn2_ctx' as
 *    the first argument to that function.  If neither is set,
 *    skAbort() is called.
 */
static int
streamLastErrFunc(
    const skstream_t       *stream,
    ssize_t                 errcode,
    sk_msg_fn_t             errfn1,
    void                   *errfn2_ctx,
    msg_fn_with_context     errfn2);


/* FUNCTION DEFINITIONS */

SK_DIAGNOSTIC_FORMAT_NONLITERAL_PUSH

/*
 *    Callback to "print" the error message into a buffer.  The buffer
 *    and its length are specified in the first argument.
 */
static int
streamLastErrMsg(
    void               *v_msg_buf,
    const char         *fmt,
    ...)
{
    stream_err_msg_buf_t *msg_buf = (stream_err_msg_buf_t*)v_msg_buf;
    va_list args;
    int rv;

    va_start(args, fmt);
    rv = vsnprintf(msg_buf->buf, msg_buf->len, fmt, args);
    va_end(args);

    return rv;
}

SK_DIAGNOSTIC_FORMAT_NONLITERAL_POP



/*
 *    Fill 'buffer' with the message that corresponds to the stream
 *    error code 'errcode'.  The stream object may provide addition
 *    context for the message.
 */
int
skStreamLastErrMessage(
    const skstream_t   *stream,
    ssize_t             errcode,
    char               *buffer,
    size_t              buffer_len)
{
    stream_err_msg_buf_t msg_buf;

    msg_buf.buf = buffer;
    msg_buf.len = buffer_len;

    return streamLastErrFunc(stream, errcode, NULL,
                             &msg_buf, &streamLastErrMsg);
}


/*
 *    Call 'errfn' to print the message that corresponds to the stream
 *    error code 'errcode'.  The stream object may provide addition
 *    context for the message.
 */
void
skStreamPrintLastErr(
    const skstream_t   *stream,
    ssize_t             errcode,
    sk_msg_fn_t         errfn)
{
    if (errfn == NULL) {
        errfn = &skAppPrintErr;
    }
    streamLastErrFunc(stream, errcode, errfn, NULL, NULL);
}


/* This function is described above. */
static int
streamLastErrFunc(
    const skstream_t       *stream,
    ssize_t                 errcode,
    sk_msg_fn_t             errfn1,
    void                   *ef2_ctx,
    msg_fn_with_context     errfn2)
{
    const char *msg;
    char t_stamp1[SKTIMESTAMP_STRLEN];
    char t_stamp2[SKTIMESTAMP_STRLEN];
    char format_name[SK_MAX_STRLEN_FILE_FORMAT+1];
    int64_t limit = 0;

#define ERR_FN(ef1_fmt_args, ef2_ctx_fmt_args)                  \
    if (errfn1) { return errfn1 ef1_fmt_args ; }                \
    else if (errfn2) { return errfn2 ef2_ctx_fmt_args ; }       \
    else { skAbort() ; }

#ifdef TEST_PRINTF_FORMATS
#undef ERR_FN
#define ERR_FN(ef1_fmt_args, ef2_ctx_fmt_args)  \
    return printf ef1_fmt_args
#endif

    /* macros for common error messages */
#define FILENAME_MSG(m)                                         \
    if (!stream) {                                              \
        ERR_FN(("%s", m),                                       \
               (ef2_ctx, "%s", m));                             \
    } else {                                                    \
        ERR_FN(("%s '%s'", m, stream->pathname),                \
               (ef2_ctx, "%s '%s'", m, stream->pathname));      \
    }

#define STRERROR_MSG(m)                                                 \
    if (!stream) {                                                      \
        ERR_FN(("%s", m),                                               \
               (ef2_ctx, "%s", m));                                     \
    }                                                                   \
    else if (stream->errnum == 0) {                                     \
        ERR_FN(("%s '%s'", m, stream->pathname),                        \
               (ef2_ctx, "%s '%s'", m, stream->pathname)); }            \
    else {                                                              \
        ERR_FN(("%s '%s': %s",                                          \
                m, stream->pathname, strerror(stream->errnum)),         \
               (ef2_ctx, "%s '%s': %s",                                 \
                m, stream->pathname, strerror(stream->errnum)));        \
    }

    switch (errcode) {
      case SKSTREAM_OK:
        FILENAME_MSG("Command completed successfully");
        break;

      case SKSTREAM_ERR_UNSUPPORT_FORMAT:
        msg = "Cannot process file given its format";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skFileFormatGetName(format_name, sizeof(format_name),
                                skHeaderGetFileFormat(stream->silk_hdr));
            ERR_FN(("%s: '%s' has format %s (0x%02x)", msg,
                    stream->pathname, format_name,
                    skHeaderGetFileFormat(stream->silk_hdr)),
                   (ef2_ctx, "%s: '%s' has format %s (0x%02x)", msg,
                    stream->pathname, format_name,
                    skHeaderGetFileFormat(stream->silk_hdr)));
        }
        break;

      case SKSTREAM_ERR_REQUIRE_SILK_FLOW:
        msg = "File does not contain SiLK Flow data";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skFileFormatGetName(format_name, sizeof(format_name),
                                skHeaderGetFileFormat(stream->silk_hdr));
            ERR_FN(("%s: '%s' has format %s (0x%02x)", msg,
                    stream->pathname, format_name,
                    skHeaderGetFileFormat(stream->silk_hdr)),
                   (ef2_ctx, "%s: '%s' has format %s (0x%02x)", msg,
                    stream->pathname, format_name,
                    skHeaderGetFileFormat(stream->silk_hdr)));
        }
        break;

      case SKSTREAM_ERR_UNSUPPORT_VERSION:
        msg = "This SiLK release does not support";
        if (!stream) {
            ERR_FN(("%s the format and version of the file", msg),
                   (ef2_ctx, "%s the format and version of the file", msg));
        } else {
            sk_file_header_t *hdr = stream->silk_hdr;
            skFileFormatGetName(format_name, sizeof(format_name),
                                skHeaderGetFileFormat(hdr));
            ERR_FN(("%s %s(0x%02x) v%u records in the v%u file '%s'", msg,
                    format_name, skHeaderGetFileFormat(hdr),
                    skHeaderGetRecordVersion(hdr), skHeaderGetFileVersion(hdr),
                    stream->pathname),
                   (ef2_ctx,
                    "%s %s(0x%02x) v%u records in the v%u file '%s'", msg,
                    format_name, skHeaderGetFileFormat(hdr),
                    skHeaderGetRecordVersion(hdr), skHeaderGetFileVersion(hdr),
                    stream->pathname));
        }
        break;

      case SKSTREAM_ERR_READ_SHORT: /* RWIO_ERR_READ_SHORT */
        msg = "Read incomplete record";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            ERR_FN(("%s (%lu of %lu bytes) from %s",
                    msg, (unsigned long)(stream->errobj.num),
                    (unsigned long)stream->recLen, stream->pathname),
                   (ef2_ctx, "%s (%lu of %lu bytes) from %s",
                    msg, (unsigned long)(stream->errobj.num),
                    (unsigned long)stream->recLen, stream->pathname));
        }
        break;

      case SKSTREAM_ERR_STIME_UNDRFLO:
        msg = "Record's start time less than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            sktimestamp_r(t_stamp1, rwRecGetStartTime(stream->errobj.rec),
                          SKTIMESTAMP_UTC);
            skStreamGetLimit(stream, errcode, &limit);
            sktimestamp_r(t_stamp2, limit, SKTIMESTAMP_UTC);
            ERR_FN(("%s '%s': %sZ < %sZ", msg,
                    stream->pathname, t_stamp1, t_stamp2),
                   (ef2_ctx, "%s '%s': %sZ < %sZ", msg,
                    stream->pathname, t_stamp1, t_stamp2));
        }
        break;

      case SKSTREAM_ERR_STIME_OVRFLO:
        msg = "Record's start time greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            sktimestamp_r(t_stamp1, rwRecGetStartTime(stream->errobj.rec),
                          SKTIMESTAMP_UTC);
            skStreamGetLimit(stream, errcode, &limit);
            sktimestamp_r(t_stamp2, limit, SKTIMESTAMP_UTC);
            ERR_FN(("%s '%s': %sZ > %sZ", msg,
                    stream->pathname, t_stamp1, t_stamp2),
                   (ef2_ctx, "%s '%s': %sZ > %sZ", msg,
                    stream->pathname, t_stamp1, t_stamp2));
        }
        break;

      case SKSTREAM_ERR_ELPSD_OVRFLO:
        msg = "Record's duration greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            /* Returned limit is milliseconds; displayed is seconds */
            skStreamGetLimit(stream, errcode, &limit);
            limit /= 1000;
            ERR_FN(("%s '%s': %u > %" PRId64, msg,
                    stream->pathname,
                    rwRecGetElapsedSeconds(stream->errobj.rec), limit),
                   (ef2_ctx, "%s '%s': %u > %" PRId64, msg,
                    stream->pathname,
                    rwRecGetElapsedSeconds(stream->errobj.rec), limit));
        }
        break;

      case SKSTREAM_ERR_PKTS_OVRFLO:
        msg = "Record's packet count greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skStreamGetLimit(stream, errcode, &limit);
            ERR_FN(("%s '%s': %u > %" PRId64, msg,
                    stream->pathname, rwRecGetPkts(stream->errobj.rec), limit),
                   (ef2_ctx, "%s '%s': %u > %" PRId64, msg,
                    stream->pathname, rwRecGetPkts(stream->errobj.rec),limit));
        }
        break;

      case SKSTREAM_ERR_PKTS_ZERO:
        FILENAME_MSG("Record's packet count is zero while writing to file");
        break;

      case SKSTREAM_ERR_BPP_OVRFLO:
        msg = "Record's byte-per-pkt ratio greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skStreamGetLimit(stream, errcode, &limit);
            ERR_FN(("%s '%s': %u > %" PRId64, msg,
                    stream->pathname, (rwRecGetBytes(stream->errobj.rec)
                                       / rwRecGetPkts(stream->errobj.rec)),
                    limit),
                   (ef2_ctx, "%s '%s': %u > %" PRId64, msg,
                    stream->pathname, (rwRecGetBytes(stream->errobj.rec)
                                       / rwRecGetPkts(stream->errobj.rec)),
                    limit));
        }
        break;

      case SKSTREAM_ERR_SNMP_OVRFLO:
        msg = "Record's SNMP index greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            const char *snmp_str = "input";
            unsigned int snmp_val = rwRecGetInput(stream->errobj.rec);
            skStreamGetLimit(stream, errcode, &limit);
            if (snmp_val <= limit) {
                snmp_str = "output";
                snmp_val = rwRecGetOutput(stream->errobj.rec);
            }
            ERR_FN(("%s '%s': %s %" PRIu16 " > %" PRId64, msg,
                    stream->pathname, snmp_str, snmp_val, limit),
                   (ef2_ctx, "%s '%s': %s %" PRIu16 " > %" PRId64, msg,
                    stream->pathname, snmp_str, snmp_val, limit));
        }
        break;

      case SKSTREAM_ERR_SENSORID_OVRFLO:
        msg = "Record's Sensor ID greater than that allowed in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skStreamGetLimit(stream, errcode, &limit);
            ERR_FN(("%s '%s': %" PRIu16 " > %" PRId64, msg,
                    stream->pathname,
                    rwRecGetSensor(stream->errobj.rec), limit),
                   (ef2_ctx, "%s '%s': %" PRIu16 " > %" PRId64, msg,
                    stream->pathname,
                    rwRecGetSensor(stream->errobj.rec), limit));
        }
        break;

      case SKSTREAM_ERR_PROTO_MISMATCH:
        msg = "Record's IP-protocol is not supported in file";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            ERR_FN(("%s '%s': %u", msg,
                    stream->pathname,
                    (unsigned int)rwRecGetProto(stream->errobj.rec)),
                   (ef2_ctx, "%s '%s': %u", msg,
                    stream->pathname,
                    (unsigned int)rwRecGetProto(stream->errobj.rec)));
        }
        break;

      case SKSTREAM_ERR_PKTS_GT_BYTES:
        msg = "Record's 'pkts' value is greater than its 'bytes' value";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            ERR_FN(("%s in file '%s': %u > %u", msg,
                    stream->pathname,
                    (unsigned int)rwRecGetPkts(stream->errobj.rec),
                    (unsigned int)rwRecGetBytes(stream->errobj.rec)),
                   (ef2_ctx, "%s in file '%s': %u > %u", msg,
                    stream->pathname,
                    (unsigned int)rwRecGetPkts(stream->errobj.rec),
                    (unsigned int)rwRecGetBytes(stream->errobj.rec)));
        }
        break;

      case SKSTREAM_ERR_UNSUPPORT_IPV6:
        FILENAME_MSG("Record has an unsupported IPv6 address");
        break;

      case SKSTREAM_ERR_ALLOC:
        ERR_FN(("Memory allocation failed"),
               (ef2_ctx, "Memory allocation failed"));
        break;

      case SKSTREAM_ERR_PREV_DATA:
        FILENAME_MSG("Initial data has already been read or written");
        break;

      case SKSTREAM_ERR_BAD_MAGIC:
        FILENAME_MSG("File does not appear to be a SiLK data file");
        break;

      case SKSTREAM_ERR_CLOSED:
        FILENAME_MSG("Cannot modify a stream once it is closed");
        break;

      case SKSTREAM_ERR_EOF:    /* RWIO_ERR_READ_EOF */
        FILENAME_MSG("Reached end of file");
        break;

      case SKSTREAM_ERR_FILE_EXISTS:
        STRERROR_MSG("Will not create new file over existing file");
        break;

      case SKSTREAM_ERR_INVALID_INPUT:
        ERR_FN(("Argument's value is invalid"),
               (ef2_ctx, "Argument's value is invalid"));
        break;

      case SKSTREAM_ERR_IOBUF:
        if (!stream) {
            ERR_FN(("Error reading/writing iobuffer"),
                   (ef2_ctx, "Error reading/writing iobuffer"));
        } else {
            ERR_FN(("Error %s iobuffer for '%s': %s",
                    ((stream->io_mode == SK_IO_READ) ? "reading" : "writing"),
                    stream->pathname, skIOBufStrError(stream->iobuf)),
                   (ef2_ctx, "Error %s iobuffer for '%s': %s",
                    ((stream->io_mode == SK_IO_READ) ? "reading" : "writing"),
                    stream->pathname, skIOBufStrError(stream->iobuf)));
        }
        break;

      case SKSTREAM_ERR_ISTERMINAL:
        if (!stream) {
            ERR_FN(("Will not read/write binary data on a terminal"),
                   (ef2_ctx, "Will not read/write binary data on a terminal"));
        } else {
            ERR_FN(("Will not %s binary data on a terminal '%s'",
                    ((stream->io_mode == SK_IO_READ) ? "read" : "write"),
                    stream->pathname),
                   (ef2_ctx, "Will not %s binary data on a terminal '%s'",
                    ((stream->io_mode == SK_IO_READ) ? "read" : "write"),
                    stream->pathname));
        }
        break;

      case SKSTREAM_ERR_LONG_LINE:
        ERR_FN(("Input string is too long"),
               (ef2_ctx, "Input string is too long"));
        break;

      case SKSTREAM_ERR_NOPAGER:
        msg = "Unable to invoke pager";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            ERR_FN(("%s '%s'",
                    msg, stream->pager),
                   (ef2_ctx, "%s '%s'",
                    msg, stream->pager));
        }
        break;

      case SKSTREAM_ERR_NOT_BOUND:
        ERR_FN(("Stream is not bound to a file"),
               (ef2_ctx, "Stream is not bound to a file"));
        break;

      case SKSTREAM_ERR_NOT_OPEN:
        FILENAME_MSG("Cannot read/write/close an unopened stream");
        break;

      case SKSTREAM_ERR_NOT_SEEKABLE:
        FILENAME_MSG("Unsupported operation---cannot seek on stream");
        break;

      case SKSTREAM_ERR_NULL_ARGUMENT:
        ERR_FN(("Unexpected NULL or empty argument"),
               (ef2_ctx, "Unexpected NULL or empty argument"));
        break;

      case SKSTREAM_ERR_PREV_BOUND:
        ERR_FN(("Cannot bind stream because it is already bound"),
               (ef2_ctx, "Cannot bind stream because it is already bound"));
        break;

      case SKSTREAM_ERR_PREV_OPEN:
        FILENAME_MSG("Stream is already open");
        break;

      case SKSTREAM_ERR_PREV_COPYINPUT:
        FILENAME_MSG("Only one copy stream is supported per input stream");
        break;

      case SKSTREAM_ERR_READ:
        STRERROR_MSG("Error reading from stream");
        break;

      case SKSTREAM_ERR_RLOCK:
        STRERROR_MSG("Cannot get read lock on file");
        break;

      case SKSTREAM_ERR_SYS_FDOPEN:
        STRERROR_MSG("Cannot convert file descriptor");
        break;

      case SKSTREAM_ERR_SYS_FORK:
        skAppPrintErr("Cannot fork");
        break;

      case SKSTREAM_ERR_SYS_LSEEK:
        STRERROR_MSG("Cannot seek on stream");
        break;

      case SKSTREAM_ERR_SYS_MKSTEMP:
        STRERROR_MSG("Cannot create temporary file");
        break;

      case SKSTREAM_ERR_SYS_OPEN:
        STRERROR_MSG("Error opening file");
        break;

      case SKSTREAM_ERR_SYS_PIPE:
        STRERROR_MSG("Cannot create pipe");
        break;

      case SKSTREAM_ERR_SYS_MKDIR:
        STRERROR_MSG("Cannot create directory component to file");
        break;

      case SKSTREAM_ERR_SYS_FCNTL_GETFL:
        STRERROR_MSG("Cannot get status flags for stream");
        break;

      case SKSTREAM_ERR_SYS_FTRUNCATE:
        STRERROR_MSG("Cannot set length of file");
        break;

      case SKSTREAM_ERR_COMPRESS_INVALID:
        msg = "Specified compression identifier is not recognized";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            ssize_t cm;
            cm = (ssize_t)skHeaderGetCompressionMethod(stream->silk_hdr);
            ERR_FN(("%s %" SK_PRIdZ " '%s'",
                    msg, cm, stream->pathname),
                   (ef2_ctx, "%s %" SK_PRIdZ " '%s'",
                    msg, cm, stream->pathname));
        }
        break;

      case SKSTREAM_ERR_COMPRESS_UNAVAILABLE:
        msg = "Specified compression method is not available";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            skCompMethodGetName(
                format_name, sizeof(format_name),
                skHeaderGetCompressionMethod(stream->silk_hdr));
            ERR_FN(("%s '%s' uses %s",
                    msg, stream->pathname, format_name),
                   (ef2_ctx, "%s '%s' uses %s",
                    msg, stream->pathname, format_name));
        }
        break;

      case SKSTREAM_ERR_UNSUPPORT_CONTENT:
        msg = "Action not supported on stream's content type";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            const char *ct = "";
            switch (stream->content_type) {
              case SK_CONTENT_SILK:
              case SK_CONTENT_SILK_FLOW:
                ct = " is SiLK";
                break;
              case SK_CONTENT_TEXT:
                ct = " is text";
                break;
              case SK_CONTENT_OTHERBINARY:
                ct = " is binary";
                break;
            }
            ERR_FN(("%s '%s'%s",
                    msg, stream->pathname, ct),
                   (ef2_ctx, "%s '%s'%s",
                    msg, stream->pathname, ct));
        }
        break;

      case SKSTREAM_ERR_UNSUPPORT_IOMODE:
        msg = "Action not permitted on stream";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            const char *io = "";
            switch (stream->io_mode) {
              case SK_IO_READ:
                io = ": read from";
                break;
              case SK_IO_WRITE:
                io = ": write to";
                break;
              case SK_IO_APPEND:
                io = ": append to";
                break;
            }
            ERR_FN(("%s%s '%s'",
                    msg, io, stream->pathname),
                   (ef2_ctx, "%s%s '%s'",
                    msg, io, stream->pathname));
        }
        break;

      case SKSTREAM_ERR_WLOCK:
        STRERROR_MSG("Cannot get write lock on file");
        break;

      case SKSTREAM_ERR_WRITE:
        STRERROR_MSG("Error writing to stream");
        break;

      case SKSTREAM_ERR_ZLIB:
        msg = "Error in zlib library";
        if (!stream) {
            ERR_FN(("%s", msg),
                   (ef2_ctx, "%s", msg));
        } else {
            int zerr = 0;
            const char *zerr_msg = NULL;
#if SK_ENABLE_ZLIB
            if (stream->gz) {
                zerr_msg = gzerror(stream->gz, &zerr);
            } else
#endif  /* SK_ENABLE_ZLIB */
            {
                zerr = stream->errnum;
            }
            if (zerr_msg) {
                ERR_FN(("%s for '%s': %s",
                        msg, stream->pathname, zerr_msg),
                       (ef2_ctx, "%s for '%s': %s",
                        msg, stream->pathname, zerr_msg));
            } else {
                ERR_FN(("%s for '%s': [%d]",
                        msg, stream->pathname, zerr),
                       (ef2_ctx, "%s for '%s': [%d]",
                        msg, stream->pathname, zerr));
            }
        }
        break;

      case SKSTREAM_ERR_IO:     /* -1 */
        if (!stream) {
            ERR_FN(("Bad read/write"),
                   (ef2_ctx, "Bad read/write"));
        } else if (stream->err_info == SKSTREAM_ERR_IO) {
            /* avoid infinite loop */
            FILENAME_MSG("Bad read/write");
        } else {
            /* call ourself with the real error code */
            return streamLastErrFunc(stream, stream->err_info,
                                     errfn1, ef2_ctx, errfn2);
        }
        break;
    }

    if (errcode > 0) {
        /* Pass it off to skheaders */
        msg = "Error processing headers";
        if (!stream) {
            ERR_FN(("%s: %s", msg, skHeaderStrerror(errcode)),
                   (ef2_ctx, "%s: %s", msg, skHeaderStrerror(errcode)));
        } else {
            ERR_FN(("%s on file '%s': %s",
                    msg, stream->pathname, skHeaderStrerror(errcode)),
                   (ef2_ctx, "%s on file '%s': %s",
                    msg, stream->pathname, skHeaderStrerror(errcode)));
        }
    }

    ERR_FN(("Unrecognized error code %" SK_PRIdZ, errcode),
           (ef2_ctx, "Unrecognized error code %" SK_PRIdZ, errcode));
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
