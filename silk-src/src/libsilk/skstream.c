/*
** Copyright (C) 2006-2023 by Carnegie Mellon University.
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
**  skstream.c
**      Mark Thomas  July-2006
**
**      skstream provides a wrapper around file pointers and file
**      descriptors.  It handles both textual and binary data.
*/


#include <silk/silk.h>

RCSIDENT("$SiLK: skstream.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/skstream.h>
#include <silk/sksite.h>
#include "skheader_priv.h"
#include "skiobuf.h"
#include "skstream_priv.h"


/* LOCAL DEFINES AND TYPEDEFS */

#ifndef DEFAULT_FILE_FORMAT
#  if SK_ENABLE_IPV6
#    define DEFAULT_FILE_FORMAT  FT_RWIPV6ROUTING
#  else
#    define DEFAULT_FILE_FORMAT  FT_RWGENERIC
#  endif
#endif


/*
 *    Name of environment variable that affects how to treat ICMP flow
 *    records.  This variable determines the setting of the
 *    'silk_icmp_nochange' global.  See the detailed note in
 *    skStreamReadRecord().
 */
#define SILK_ICMP_SPORT_HANDLER_ENVAR "SILK_ICMP_SPORT_HANDLER"


/*
 *    Return SKSTREAM_ERR_NULL_ARGUMENT when 'srin_stream' is NULL.
 */
#define STREAM_RETURN_IF_NULL(srin_stream) \
    if (NULL == (srin_stream)) { return SKSTREAM_ERR_NULL_ARGUMENT; }


/*
 *    Set the 'is_silk_flow' bit on 'stream' if the format of the
 *    header indicates it contains SiLK Flow records.
 */
#define STREAM_SET_IS_SILK_FLOW(stream)                         \
    switch (skHeaderGetFileFormat((stream)->silk_hdr)) {        \
      case FT_RWAUGMENTED:                                      \
      case FT_RWAUGROUTING:                                     \
      case FT_RWAUGWEB:                                         \
      case FT_RWAUGSNMPOUT:                                     \
      case FT_RWFILTER:                                         \
      case FT_FLOWCAP:                                          \
      case FT_RWGENERIC:                                        \
      case FT_RWIPV6:                                           \
      case FT_RWIPV6ROUTING:                                    \
      case FT_RWNOTROUTED:                                      \
      case FT_RWROUTED:                                         \
      case FT_RWSPLIT:                                          \
      case FT_RWWWW:                                            \
        (stream)->is_silk_flow = 1;                             \
        break;                                                  \
      default:                                                  \
        (stream)->is_silk_flow = 0;                             \
        break;                                                  \
    }


/* LOCAL VARIABLES */

/*
 *    If nonzero, do not attempt process ICMP values in the sPort
 *    field.  This is 0 unless the SILK_ICMP_SPORT_HANDLER envar is
 *    set to "none".  See the detailed note in skStreamReadRecord().
 */
static int silk_icmp_nochange = 0;

#ifdef SILK_CLOBBER_ENVAR
/*
 *    If nonzero, enable clobbering (overwriting) of existing files
 */
static int silk_clobber = 0;
#endif


/* LOCAL FUNCTION PROTOTYPES */

static ssize_t
streamIOBufCallbackRead(
    skstream_t         *stream,
    void               *buf,
    size_t              count);

static ssize_t
streamIOBufCallbackWrite(
    skstream_t         *stream,
    const void         *buf,
    size_t              count);

static off_t
streamIOBufCallbackSeek(
    skstream_t         *stream,
    off_t               offset,
    int                 whence);

/* FUNCTION DEFINITIONS */

/*
 *    Update 'stream' with the sensor, type, and starting-hour stored
 *    in the stream's header if 'stream' is bound to a packed hourly
 *    data file.
 */
static void
streamCacheHeader(
    skstream_t         *stream)
{
    const sk_header_entry_t *hentry;

    assert(stream);
    assert(stream->is_silk_flow);

    hentry = skHeaderGetFirstMatch(stream->silk_hdr, SK_HENTRY_PACKEDFILE_ID);
    if (hentry) {
        stream->hdr_starttime = skHentryPackedfileGetStartTime(hentry);
        stream->hdr_sensor    = skHentryPackedfileGetSensorID(hentry);
        stream->hdr_flowtype  = skHentryPackedfileGetFlowtypeID(hentry);
    }
}


/*
 *    Return an error string representing the most recent error that
 *    occurred on 'stream'.
 *
 *    This function is a callback invoked by skIOBufStrError().
 */
static const char *
streamCallbackStrerror(
    skstream_t         *stream,
    int          UNUSED(errnum))
{
    if (stream->err_info == SKSTREAM_ERR_ZLIB) {
#if SK_ENABLE_ZLIB
        if (stream->gz) {
            int zerr;
            return gzerror(stream->gz, &zerr);
        }
#endif  /* SK_ENABLE_ZLIB */
        return "Interal zlib error";
    }
    return strerror(stream->errnum);
}


/*
 *  status = streamCheckAttributes(stream, io_mode_list, content_type_list);
 *
 */
static int
streamCheckAttributes(
    skstream_t         *stream,
    int                 io_mode_list,
    int                 content_type_list)
{
    assert(stream);
    if ( !(stream->io_mode & io_mode_list)) {
        return SKSTREAM_ERR_UNSUPPORT_IOMODE;
    } else if ( !(stream->content_type & content_type_list)) {
        return SKSTREAM_ERR_UNSUPPORT_CONTENT;
    } else {
        return SKSTREAM_OK;
    }
}


/*
 *  status = streamCheckModifiable(stream);
 *
 *    Return SKSTREAM_OK if the caller is still allowed to set aspects
 *    of 'stream'; otherwise return the reason why 'stream' cannot be
 *    modified.
 */
static int
streamCheckModifiable(
    skstream_t         *stream)
{
    assert(stream);
    if (stream->is_closed) {
        return SKSTREAM_ERR_CLOSED;
    } else if (stream->is_dirty) {
        return SKSTREAM_ERR_PREV_DATA;
    } else {
        return SKSTREAM_OK;
    }
}


/*
 *  status = streamCheckOpen(stream);
 *
 *    Call this function on a stream which you expect to be open; it
 *    will return SKSTREAM_OK if 'stream' is open, or an error code
 *    explaining why 'stream' is not open.
 *
 *    A stream that has been opened and closed is neither open nor
 *    unopened.
 */
static int
streamCheckOpen(
    const skstream_t   *stream)
{
    assert(stream);
    if (stream->is_closed) {
        return SKSTREAM_ERR_CLOSED;
    } else if (stream->fd == -1) {
        return SKSTREAM_ERR_NOT_OPEN;
    } else {
        return SKSTREAM_OK;
    }
}


/*
 *  status = streamCheckUnopened(stream);
 *
 *    Call this function on a stream which you expect to be
 *    unopened---i.e., not yet open.  It will return SKSTREAM_OK if
 *    'stream' is unopened, or an error code explaining why 'stream'
 *    is not considered unopened.
 *
 *    A stream that has been opened and closed is neither open nor
 *    unopened.
 */
static int
streamCheckUnopened(
    const skstream_t   *stream)
{
    assert(stream);
    if (stream->is_closed) {
        return SKSTREAM_ERR_CLOSED;
    } else if (stream->fd != -1) {
        return SKSTREAM_ERR_PREV_OPEN;
    } else {
        return SKSTREAM_OK;
    }
}


#if SK_ENABLE_ZLIB
/*
 *  status = streamGZFlush(stream);
 *
 *    Tell the zlib descriptor associated with 'stream' to flush any
 *    unwritten data to the stream.
 *
 *    This function is invoked directly by other skstream functions
 *    and it is a callback invoked by skIOBufFlush().
 */
static int
streamGZFlush(
    skstream_t         *stream)
{
    int zerr = gzflush(stream->gz, Z_SYNC_FLUSH);
    if (zerr == Z_OK) {
        return 0;
    }
    stream->is_iobuf_error = 1;
    if (zerr == Z_ERRNO) {
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_WRITE;
    } else {
        stream->errnum = zerr;
        stream->err_info = SKSTREAM_ERR_ZLIB;
    }
    return -1;
}


/*
 *  status = streamGZRead(stream, buf, count);
 *
 *    Read 'count' bytes from the zlib descriptor associated with
 *    'stream' and put them into 'buf'.
 *
 *    This function is invoked directly by other skstream functions
 *    and it is a callback invoked by skIOBufRead().
 */
static ssize_t
streamGZRead(
    skstream_t         *stream,
    void               *buf,
    size_t              count)
{
    int got = gzread(stream->gz, buf, (unsigned)count);
    if (got == -1) {
        stream->is_iobuf_error = 1;
        (void)gzerror(stream->gz, &stream->errnum);
        if (stream->errnum == Z_ERRNO) {
            stream->errnum = errno;
            stream->err_info = SKSTREAM_ERR_READ;
        } else {
            stream->err_info = SKSTREAM_ERR_ZLIB;
        }
    }
    return (ssize_t)got;
}


/*
 *  status = streamGZRead(stream, buf, count);
 *
 *    Write 'count' bytes from 'buf' to the zlib descriptor associated
 *    with 'stream'.
 *
 *    This function is invoked directly by other skstream functions
 *    and it is a callback invoked by skIOBufWrite().
 */
static ssize_t
streamGZWrite(
    skstream_t         *stream,
    const void         *buf,
    size_t              count)
{
    int written = gzwrite(stream->gz, buf, (unsigned)count);
    if (written > 0 || count == 0) {
        return written;
    }
    stream->is_iobuf_error = 1;
    (void)gzerror(stream->gz, &stream->errnum);
    if (stream->errnum == Z_ERRNO) {
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_WRITE;
    } else {
        stream->err_info = SKSTREAM_ERR_ZLIB;
    }
    return -1;
}
#endif  /* SK_ENABLE_ZLIB */


/*
 *  status = streamIOBufCreate(stream);
 *
 *    Create the skIOBuf that 'stream' will read-from/write-to, and
 *    bind it to the file descriptor or gzfile.  Return SKSTREAM_OK on
 *    success, or an error code on failure.
 */
static int
streamIOBufCreate(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;
    uint8_t compmethod = SK_COMPMETHOD_NONE;
    skio_abstract_t io_func;

    assert(stream);
    assert(stream->fd != -1);

    if (stream->is_unbuffered) {
        goto END;
    }

    memset(&io_func, 0, sizeof(skio_abstract_t));

    /* make certain compression method is available */
    if (stream->is_silk) {
        compmethod = skHeaderGetCompressionMethod(stream->silk_hdr);
        switch (skCompMethodCheck(compmethod)) {
          case SK_COMPMETHOD_IS_AVAIL:
            /* known, valid, and available */
            break;
          case SK_COMPMETHOD_IS_VALID:
            /* known and valid but not available */
            rv = SKSTREAM_ERR_COMPRESS_UNAVAILABLE;
            goto END;
          case SK_COMPMETHOD_IS_KNOWN:
            /* should never be undecided at this point */
            skAbort();
          default:
            rv = SKSTREAM_ERR_COMPRESS_INVALID;
            goto END;
        }
    }

    /* store location where the IOBuf was enabled */
    stream->pre_iobuf_pos = lseek(stream->fd, 0, SEEK_CUR);

    /* create the iobuf */
    switch (stream->io_mode) {
      case SK_IO_READ:
        /* create the buffered reader */
        stream->iobuf = skIOBufCreate(stream->io_mode);
        break;

      case SK_IO_WRITE:
      case SK_IO_APPEND:
        stream->iobuf = skIOBufCreate(stream->io_mode);
        break;
    }
    if (stream->iobuf == NULL) {
        rv = SKSTREAM_ERR_ALLOC;
        goto END;
    }

    /* get the information for SiLK files */
    if (stream->is_silk) {
        /* make certain the record size is non-zero */
        size_t reclen;
        reclen = skHeaderGetRecordLength(stream->silk_hdr);
        if (reclen == 0) {
            reclen = 1;
            skHeaderSetRecordLength(stream->silk_hdr, reclen);
        }

        /* set the record size on the IOBuf */
        if (-1 == skIOBufSetRecordSize(stream->iobuf, reclen)) {
            rv = SKSTREAM_ERR_IOBUF;
            goto END;
        }
    }

    /* bind it to the file descriptor or gzfile */
#if SK_ENABLE_ZLIB
    if (stream->gz) {
        io_func.read = (skio_read_fn_t)&streamGZRead;
        io_func.write = (skio_write_fn_t)&streamGZWrite;
        io_func.seek = NULL;
        io_func.flush = (skio_flush_fn_t)&streamGZFlush;
        io_func.strerror = (skio_strerror_fn_t)&streamCallbackStrerror;
        if (skIOBufBindAbstract(stream->iobuf, stream, compmethod, &io_func)
            == -1)
        {
            rv = SKSTREAM_ERR_IOBUF;
            goto END;
        }
    } else
#endif  /* SK_ENABLE_ZLIB */
    {
        /* if (skIOBufBind(stream->iobuf, stream->fd, compmethod) == -1) */
        io_func.read = (skio_read_fn_t)&streamIOBufCallbackRead;
        io_func.write = (skio_write_fn_t)&streamIOBufCallbackWrite;
        io_func.seek = (skio_seek_fn_t)&streamIOBufCallbackSeek;
        io_func.strerror = (skio_strerror_fn_t)&streamCallbackStrerror;
        if (skIOBufBindAbstract(stream->iobuf, stream, compmethod, &io_func)
            == -1)
        {
            rv = SKSTREAM_ERR_IOBUF;
            goto END;
        }
    }

  END:
    return rv;
}


/*
 *  status = streamIOBufGetLine(stream, out_buffer, buf_size);
 *
 *   Fill 'out_buffer' with the next '\n'-delimited line of text from
 *   the IOBuf associated with the 'stream'.  The '\n' is replaced
 *   with '\0'.  If the final input is smaller than 'buf_size' and
 *   does not contain a '\n' it will be copied into 'out_buffer'.
 *   Return SKSTREAM_OK on success.
 *
 *   If there is no '\n' within the first 'buf_size' characters of the
 *   input, return SKSTREAM_ERR_LONG_LINE and read from the IOBuf
 *   until a '\n' is found or until end-of-file is reached.
 *
 *   Return SKSTREAM_ERR_EOF when all input data has been processed.
 *
 *   Return SKSTREAM_ERR_IOBUF is there is a problem reading from the
 *   IOBuf.
 *
 *   This function mimics fgets().
 */
static int
streamIOBufGetLine(
    skstream_t         *stream,
    char               *out_buffer,
    size_t              buf_size)
{
    char *eol = NULL;
    ssize_t sz;
    int rv = SKSTREAM_OK;

    while (eol == NULL) {
        /* substract 1 for final '\0' */
        sz = skIOBufReadToChar(stream->iobuf, out_buffer, buf_size-1, '\n');
        if (sz == -1) {
            if (stream->is_iobuf_error) {
                stream->is_iobuf_error = 0;
                rv = stream->err_info;
            } else {
                rv = SKSTREAM_ERR_IOBUF;
            }
            break;
        }
        if (sz == 0) {
            rv = SKSTREAM_ERR_EOF;
            break;
        }
        if ((sz == (ssize_t)buf_size-1) && ('\n' != out_buffer[sz-1])) {
            /* Found no newline in 'buf_size' characters... */
            rv = SKSTREAM_ERR_LONG_LINE;
            /* need to read more from skiobuf to find next '\n' */
            continue;
        }

        /* NUL terminate the string, either by replacing '\n' with a
         * '\0', or by putting a '\0' after the final character. */
        eol = &out_buffer[sz-1];
        if (*eol != '\n') {
            ++eol;
        }
        *eol = '\0';
    }

    return rv;
}


/*
 *  status = streamIOBufCallbackRead(stream, buf, count);
 *
 *    Read 'count' bytes from the file descriptor associated with
 *    'stream' and put them into 'buf'.
 *
 *    This function is a callback invoked by skIOBufRead().
 */
static ssize_t
streamIOBufCallbackRead(
    skstream_t         *stream,
    void               *buf,
    size_t              count)
{
    ssize_t rv;

    rv = skreadn(stream->fd, buf, count);
    if (rv == -1) {
        stream->is_iobuf_error = 1;
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_READ;
    }
    return rv;
}


/*
 *  status = streamIOBufCallbackWrite(stream, buf, count);
 *
 *    Write 'count' bytes from 'buf' to the file descriptor associated
 *    with 'stream'.
 *
 *    This function is a callback invoked by skIOBufWrite().
 */
static ssize_t
streamIOBufCallbackWrite(
    skstream_t         *stream,
    const void         *buf,
    size_t              count)
{
    ssize_t rv;

    rv = skwriten(stream->fd, buf, count);
    if (rv == -1) {
        stream->is_iobuf_error = 1;
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_WRITE;
    }
    return rv;
}


/*
 *  status = streamIOBufCallbackSeek(stream, offset, whence);
 *
 *    Seeks to a location in 'stream' from 'whence' modified by 'offset'.
 *
 *    This function is a callback invoked by skIOBufRead() when the
 *    buffer in which to return the data is NULL.
 */
static off_t
streamIOBufCallbackSeek(
    skstream_t         *stream,
    off_t               offset,
    int                 whence)
{
    off_t rv;

    rv = lseek(stream->fd, offset, whence);
    if (rv == (off_t)(-1)) {
        if (errno != ESPIPE) {
            stream->is_iobuf_error = 1;
            stream->errnum = errno;
            stream->err_info = SKSTREAM_ERR_SYS_LSEEK;
        }
    }
    return rv;
}


/*
 *    If a pager has been set on 'stream' and 'stream' is connected to
 *    a terminal, invoke the pager.
 */
static int
streamInvokePager(
    skstream_t         *stream)
{
    int rv;
    pid_t pid;
    int wait_status;

    rv = streamCheckModifiable(stream);
    if (rv) { goto END; }

    assert(streamCheckAttributes(stream, SK_IO_WRITE, SK_CONTENT_TEXT)
           == SKSTREAM_OK);

    if (stream->pager == NULL) {
        goto END;
    }

    if ( !stream->is_terminal) {
        goto END;
    }

#if 1
    /* invoke the pager */
    stream->fp = popen(stream->pager, "w");
    if (NULL == stream->fp) {
        rv = SKSTREAM_ERR_NOPAGER;
        goto END;
    }

    /* see if pager started.  There is a race condition here, and this
     * assumes we have only one child, which should be true. */
    pid = wait4(0, &wait_status, WNOHANG, NULL);
    if (pid) {
        rv = SKSTREAM_ERR_NOPAGER;
        goto END;
    }
#else
    {
    int pipe_des[2];

    /* create pipe and fork */
    if (pipe(pipe_des) == -1) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_PIPE;
        goto END;
    }
    pid = fork();
    if (pid < 0) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_FORK;
        goto END;
    }

    if (pid == 0) {
        /* CHILD */

        /* close output side of pipe; set input to stdin */
        close(pipe_des[1]);
        if (pipe_des[0] != STDIN_FILENO) {
            dup2(pipe_des[0], STDIN_FILENO);
            close(pipe_des[0]);
        }

        /* invoke pager */
        execlp(pager, NULL);
        skAppPrintErr("Unable to invoke pager '%s': %s",
                      pager, strerror(errno));
        _exit(EXIT_FAILURE);
    }

    /* PARENT */

    /* close input side of pipe */
    close(pipe_des[0]);

    /* try to open the write side of the pipe */
    out = fdopen(pipe_des[1], "w");
    if (NULL == out) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_FDOPEN;
        goto END;
    }

    /* it'd be nice to have a slight pause here to give child time to
     * die if command cannot be exec'ed, but it's not worth the
     * trouble to use select(), and sleep(1) is too long. */

    /* see if child died unexpectedly */
    if (waitpid(pid, &wait_status, WNOHANG)) {
        rv = SKSTREAM_ERR_NOPAGER;
        goto END;
    }
    }
#endif /* 1: whether to use popen() */

    /* looks good. */
    stream->is_pager_active = 1;

  END:
    return rv;
}




/*
 *  status = streamOpenAppend(stream);
 *
 *    Open the stream for appending.
 */
static int
streamOpenAppend(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;
    int flags = O_RDWR | O_APPEND;

    assert(stream);
    assert(stream->pathname);

    /* Open file for read and write; position at start. */
    stream->fd = open(stream->pathname, flags, 0);
    if (stream->fd == -1) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_OPEN;
        goto END;
    }
    if (-1 == lseek(stream->fd, 0, SEEK_SET)) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_LSEEK;
        goto END;
    }

  END:
    return rv;
}


/*
 *    Bind the currently open file descriptor to zlib via gzdopen().
 *    When reading a stream and the underlying file is seekable, do
 *    not bind the descriptor to zlib when the GZIP magic numbers are
 *    not present.
 */
static int
streamOpenGzip(
    skstream_t         *stream)
{
    int is_compressed = 1;
    ssize_t num_read;
    uint8_t magic[3];
    int rv = SKSTREAM_OK;

    if (stream->io_mode == SK_IO_READ && stream->is_seekable) {
        /* Read the first two characters to look for the GZIP magic
         * number (31 139 (see RFC1952)) to see if the stream really
         * is compressed. */
        num_read = read(stream->fd, magic, 2);
        if ((num_read != 2) || (magic[0] != 31u) || (magic[1] != 139u)) {
            /* File does not contain the gzip magic number. */
            is_compressed = 0;
        }
        if (0 != lseek(stream->fd, 0, SEEK_SET)) {
            rv = SKSTREAM_ERR_SYS_LSEEK;
            goto END;
        }
    }

    if (is_compressed) {
#if SK_ENABLE_ZLIB
        stream->gz = gzdopen(stream->fd,
                             (stream->io_mode == SK_IO_READ) ? "rb" : "wb");
        if (stream->gz == NULL) {
            rv = SKSTREAM_ERR_ALLOC;
            goto END;
        }
#else
        /* compression not supported */
        rv = SKSTREAM_ERR_COMPRESS_UNAVAILABLE;
        goto END;
#endif /* SK_ENABLE_ZLIB */
    }

  END:
    return rv;
}


/*
 *  status = streamOpenRead(stream);
 *
 *    Open the stream for reading.
 */
static int
streamOpenRead(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;

    assert(stream);
    assert(stream->pathname);
    assert(stream->io_mode == SK_IO_READ);
    assert(-1 == stream->fd);

    if (stream->is_mpi) {
        /* for now, just set to a valid value.  we should replace the
         * checks of 'fd' with an 'is_open' flag */
        stream->fd = INT32_MAX;
    } else if ((0 == strcmp(stream->pathname, "stdin"))
               || (0 == strcmp(stream->pathname, "-")))
    {
        stream->fd = STDIN_FILENO;
        stream->is_stdio = 1;
    } else {
        stream->fd = open(stream->pathname, O_RDONLY);
        if (stream->fd == -1) {
            rv = SKSTREAM_ERR_SYS_OPEN;
            stream->errnum = errno;
            goto END;
        }
    }

  END:
    /* if something went wrong, close the file */
    if (rv != SKSTREAM_OK) {
        if (stream->fd != -1) {
            close(stream->fd);
            stream->fd = -1;
        }
    }
    return rv;
}


static int
streamOpenWrite(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;

    assert(stream);
    assert(stream->pathname);
    assert(stream->io_mode == SK_IO_WRITE);

    if ((0 == strcmp(stream->pathname, "stdout"))
        || (0 == strcmp(stream->pathname, "-")))
    {
        stream->fd = STDOUT_FILENO;
        stream->is_stdio = 1;
    } else if (0 == strcmp(stream->pathname, "stderr")) {
        stream->fd = STDERR_FILENO;
        stream->is_stdio = 1;
    } else if (stream->is_mpi) {
        /* for now, just set to a valid value.  we should replace the
         * checks of 'fd' with an 'is_open' flag */
        stream->fd = INT32_MAX;
    } else {
        struct stat stbuf;
        int mode, flags;

        /* standard mode of 0666 */
        mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

        /* assume creating previously non-existent file */
        flags = O_WRONLY | O_CREAT | O_EXCL;

        /* try to open as a brand new file */
        stream->fd = open(stream->pathname, flags, mode);
        if (stream->fd == -1) {
            stream->errnum = errno;
            if ((stream->errnum == EEXIST)
                && (0 == stat(stream->pathname, &stbuf)))
            {
                /* file exists.  Try again with different flags when
                 * the file is a FIFO, the file is a character device
                 * ("/dev/null"), or the SILK_CLOBBER envar is set. */
                if (S_ISFIFO(stbuf.st_mode)) {
                    flags = O_WRONLY;
                } else if (S_ISCHR(stbuf.st_mode)) {
                    flags = O_WRONLY | O_NOCTTY;
#ifdef SILK_CLOBBER_ENVAR
                } else if (silk_clobber) {
                    /* overwrite an existing file */
                    flags = O_WRONLY | O_TRUNC;
#endif  /* SILK_CLOBBER_ENVAR */
                } else {
                    rv = SKSTREAM_ERR_FILE_EXISTS;
                    goto END;
                }

                /* try again with the new flags */
                stream->fd = open(stream->pathname, flags, mode);
            }

            /* if we (still) have an error, return */
            if (stream->fd == -1) {
                /* we set errnum above */
                rv = SKSTREAM_ERR_SYS_OPEN;
                goto END;
            }
        }
    }

  END:
    return rv;
}


/*
 *  is_compressed = streamPathnameIsCompressed(pathname, io_mode);
 *
 *    Return TRUE if 'pathname' should be considered a compressed file
 *    for the given IO mode---that is, where the entire file is
 *    compressed---or FALSE otherwise.
 *
 *    Basically, returns TRUE when 'pathname' ends in ".gz" or when it
 *    is open for reading and contains the substring ".gz."---assuming
 *    the pathname has had a mkstemp() suffix added to it.  In all
 *    other cases, it returns FALSE.
 */
static int
streamPathnameIsCompressed(
    const char         *pathname,
    skstream_mode_t     read_write_append)
{
    const char *gz;

    gz = strstr(pathname, ".gz");
    if (gz != NULL) {
        switch (read_write_append) {
          case SK_IO_READ:
          case SK_IO_APPEND:
            if (gz[3] == '.') {
                return 1;
            }
            /* FALLTHROUGH */

          case SK_IO_WRITE:
            if (gz[3] == '\0') {
                return 1;
            }
            break;
        }
    }
    return 0;
}


static int
streamPostOpen(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;

    assert(stream);
    assert(stream->fd != -1);

    if (!stream->is_mpi) {
        if (isatty(stream->fd)) {
            stream->is_terminal = 1;
        } else if (lseek(stream->fd, 0, SEEK_CUR) != (off_t)-1) {
            stream->is_seekable = 1;
        }

        /* handle compressed files */
        if (streamPathnameIsCompressed(stream->pathname, stream->io_mode)) {
            rv = streamOpenGzip(stream);
            if (rv) { goto END; }
        }
    }

    /* for a non-silk binary file, create the IOBuf now.  If the
     * stream was open for appending, seek to the end of the file
     * before creating the IOBuf */
    if (stream->content_type == SK_CONTENT_OTHERBINARY) {
        if (stream->io_mode == SK_IO_APPEND) {
            if (-1 == lseek(stream->fd, 0, SEEK_END)) {
                stream->errnum = errno;
                rv = SKSTREAM_ERR_SYS_LSEEK;
                goto END;
            }
        }

        rv = streamIOBufCreate(stream);
        if (rv) { goto END; }
    }

    /* for a text file we are reading, create the IOBuf now */
    if (stream->content_type == SK_CONTENT_TEXT
        && stream->io_mode == SK_IO_READ)
    {
        rv = streamIOBufCreate(stream);
        if (rv) { goto END; }
    }

  END:
    return rv;
}


/*
 *    Invoke the SiLK Flow file format-specific function that sets the
 *    rwUnpackFn() and rwPackFn() function pointers on 'stream'.
 */
static int
streamPrepareFormat(
    skstream_t         *stream)
{
    assert(stream);
    assert(stream->is_silk);
    assert(stream->silk_hdr);

    switch (skHeaderGetFileFormat(stream->silk_hdr)) {
      case FT_RWAUGMENTED:
        return augmentedioPrepare(stream);

      case FT_RWAUGROUTING:
        return augroutingioPrepare(stream);

      case FT_RWAUGWEB:
        return augwebioPrepare(stream);

      case FT_RWAUGSNMPOUT:
        return augsnmpoutioPrepare(stream);

      case FT_RWFILTER:
        return filterioPrepare(stream);

      case FT_FLOWCAP:
        return flowcapioPrepare(stream);

      case FT_RWGENERIC:
        return genericioPrepare(stream);

      case FT_RWIPV6:
        stream->supports_ipv6 = 1;
        return ipv6ioPrepare(stream);

      case FT_RWIPV6ROUTING:
        stream->supports_ipv6 = 1;
        return ipv6routingioPrepare(stream);

      case FT_RWNOTROUTED:
        return notroutedioPrepare(stream);

      case FT_RWROUTED:
        return routedioPrepare(stream);

      case FT_RWSPLIT:
        return splitioPrepare(stream);

      case FT_RWWWW:
        return wwwioPrepare(stream);

      default:
        break;
    }

    return SKSTREAM_ERR_UNSUPPORT_FORMAT;
}


/*
 *   Prepare 'stream' for writing textual output.  The function uses
 *   fdopen() to get a file pointer for the file descriptor when
 *   'stream' is open for write or append.  If a pager is defined for
 *   'stream', the pager is invoked.
 *
 *   For processing textual input, skstream uses an IO Buf.
 */
static int
streamPrepareText(
    skstream_t         *stream)
{
    int rv;

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    assert(!stream->is_binary);

    if (stream->fp == NULL) {
        const char *mode = NULL;
        switch (stream->io_mode) {
          case SK_IO_READ:
            break;

          case SK_IO_WRITE:
            if (stream->pager) {
                rv = streamInvokePager(stream);
                if (rv) { goto END; }
            }
            if (stream->fp == NULL) {
                mode = "w";
            }
            break;

          case SK_IO_APPEND:
            mode = "r+";
            break;
        }
        if (mode) {
            stream->fp = fdopen(stream->fd, mode);
            if (stream->fp == NULL) {
                stream->errnum = errno;
                rv = SKSTREAM_ERR_SYS_FDOPEN;
                goto END;
            }
        }
    }

    stream->is_dirty = 1;

  END:
    return rv;
}


/*
 *  bytes = streamReadNullBuffer(stream, count);
 *
 *    Read 'count' bytes from 'stream', ignoring the data.  Return the
 *    number of bytes read, or -1 for an error.
 */
static ssize_t
streamReadNullBuffer(
    skstream_t         *stream,
    const size_t        count)
{
    uint8_t buf[65536];
    size_t left = count;
    size_t wanted;
    ssize_t saw;

    assert(stream);
    assert(stream->io_mode == SK_IO_READ || stream->io_mode == SK_IO_APPEND);
    assert(stream->fd != -1);
    assert(stream->iobuf == NULL);

#if SK_ENABLE_ZLIB
    if (stream->gz != NULL) {
        while (left) {
            /* don't read more than will fit into our buffer */
            wanted = ((left < sizeof(buf)) ? left : sizeof(buf));

            saw = streamGZRead(stream, buf, wanted);
            if (saw == -1) {
                stream->is_iobuf_error = 0;
                return saw;
            }
            if (saw == 0) {
                /* no more to read */
                break;
            }

            left -= saw;
        }

        return (count - left);
    }
#endif  /* SK_ENABLE_ZLIB */

    while (left) {
        /* don't read more than will fit into our buffer */
        wanted = ((left < sizeof(buf)) ? left : sizeof(buf));

        saw = skreadn(stream->fd, buf, wanted);
        if (saw == -1) {
            stream->errnum = errno;
            stream->err_info = SKSTREAM_ERR_READ;
            return saw;
        }
        if (saw == 0) {
            /* no more to read */
            break;
        }
        left -= saw;
    }

    return (count - left);
}


/*
 *    Read 'skip_count' records from 'stream'.  If 'records_skipped'
 *    is not NULL, fill the location it references with the number of
 *    records actually skipped.
 *
 *    This function is only invoked when an IO Buf is NOT associated
 *    with 'stream' and when the 'copyInputFD' member of 'stream' is
 *    NULL.
 */
static int
streamSkipRecordsNonIOBuf(
    skstream_t         *stream,
    size_t              skip_count,
    size_t             *records_skipped)
{
#define SKIP_RECORD_COUNT  1024
    uint8_t ar[SKIP_RECORD_COUNT * SK_MAX_RECORD_SIZE];
    ssize_t saw;
    ssize_t tmp;

    assert(stream);
    assert(records_skipped);

    if (stream->is_eof) {
        return SKSTREAM_ERR_EOF;
    }

    while (skip_count > 0) {
        /* can only read the number of records our buffer allows */
        if (skip_count > SKIP_RECORD_COUNT) {
            tmp = stream->recLen * SKIP_RECORD_COUNT;
        } else {
            tmp = stream->recLen * skip_count;
        }

        /* read the bytes and check for error or short reads */
        saw = skStreamRead(stream, ar, tmp);
        if (saw != tmp) {
            /* Either error or an incomplete read--assume end of file */
            stream->is_eof = 1;
            if (saw == -1) {
                /* error */
                return -1;
            }
        }

        /* compute the number of records we actually read, update
         * counters, and check for any partially read records. */
        tmp = (saw / stream->recLen);
        stream->rec_count += tmp;
        skip_count -= tmp;
        saw -= tmp * stream->recLen;
        *records_skipped += tmp;

        if (saw != 0) {
            stream->errobj.num = saw;
            return SKSTREAM_ERR_READ_SHORT;
        }
        if (stream->is_eof) {
            return SKSTREAM_ERR_EOF;
        }
    }

    return SKSTREAM_OK;
}


/*
 * *********************************
 * PUBLIC / EXPORTED FUNCTIONS
 * *********************************
 */

/*
 *  status = skStreamBind(stream, path);
 *
 *    Set 'stream' to operate on the file specified in 'path'; 'path'
 *    may also be one of "stdin", "stdout", or "stderr".  Returns
 *    SKSTREAM_OK on success, or an error code on failure.
 */
int
skStreamBind(
    skstream_t         *stream,
    const char         *pathname)
{
    int rv = SKSTREAM_OK;
    FILE *s = NULL;

    /* check name */
    if (NULL == stream || NULL == pathname) {
        rv = SKSTREAM_ERR_NULL_ARGUMENT;
        goto END;
    }
    if ('\0' == *pathname || strlen(pathname) >= PATH_MAX) {
        rv = SKSTREAM_ERR_INVALID_INPUT;
        goto END;
    }
    if (stream->pathname) {
        rv = SKSTREAM_ERR_PREV_BOUND;
        goto END;
    }

    /* copy it into place */
    stream->pathname = strdup(pathname);
    if (stream->pathname == NULL) {
        rv = SKSTREAM_ERR_ALLOC;
        goto END;
    }

    if (0 == strcmp(pathname, "stdin")) {
        switch (stream->io_mode) {
          case SK_IO_READ:
            if (!stream->is_mpi && stream->is_binary && FILEIsATty(stdin)) {
                rv = SKSTREAM_ERR_ISTERMINAL;
                goto END;
            }
            break;
          case SK_IO_WRITE:
          case SK_IO_APPEND:
            /* cannot write or append to stdin */
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
    } else if (0 == strcmp(pathname, "stdout")) {
        s = stdout;
    } else if (0 == strcmp(pathname, "stderr")) {
        s = stderr;
    } else if (0 == strcmp(pathname, "-")) {
        switch (stream->io_mode) {
          case SK_IO_READ:
            if (!stream->is_mpi && stream->is_binary && FILEIsATty(stdin)) {
                rv = SKSTREAM_ERR_ISTERMINAL;
                goto END;
            }
            break;
          case SK_IO_WRITE:
            s = stdout;
            break;
          case SK_IO_APPEND:
            /* cannot append to stdout */
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
    }

    if (s) {
        switch (stream->io_mode) {
          case SK_IO_READ:
          case SK_IO_APPEND:
            /* cannot read or append to stdout/stderr */
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
          case SK_IO_WRITE:
            if (!stream->is_mpi && stream->is_binary && FILEIsATty(s)) {
                rv = SKSTREAM_ERR_ISTERMINAL;
                goto END;
            }
            break;
        }
    }

    /* cannot append to FIFOs or to gzipped files */
    if (stream->io_mode == SK_IO_APPEND) {
        if (streamPathnameIsCompressed(stream->pathname, stream->io_mode)) {
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
        if (isFIFO(pathname)) {
            /* Cannot append to a FIFO */
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
    }

  END:
    return (stream->last_rv = rv);
}


int
skStreamCheckCompmethod(
    skstream_t         *stream,
    sk_msg_fn_t         errfn)
{
#ifdef TEST_PRINTF_FORMATS
#  define P_ERR printf
#else
#  define P_ERR if (!errfn) { } else errfn
#endif
    sk_compmethod_t compmethod;

    compmethod = skHeaderGetCompressionMethod(stream->silk_hdr);
    switch (skCompMethodCheck(compmethod)) {
      case SK_COMPMETHOD_IS_AVAIL:
        /* known, valid, and available */
        return (stream->last_rv = SKSTREAM_OK);
      case SK_COMPMETHOD_IS_VALID:
        /* known and valid but not available */
        if (errfn) {
            char name[64];
            skCompMethodGetName(name, sizeof(name), compmethod);
            P_ERR("The %s compression method used by '%s' is not available",
                  name, stream->pathname);
        }
        return (stream->last_rv = SKSTREAM_ERR_COMPRESS_UNAVAILABLE);
      case SK_COMPMETHOD_IS_KNOWN:
        /* this is an undecided value, only valid for write */
        if (SK_IO_WRITE == stream->io_mode) {
            return (stream->last_rv = SKSTREAM_OK);
        }
        /* FALLTHROUGH */
      default:
        if (errfn) {
            P_ERR("File '%s' is compressed with an unrecognized method %d",
                  stream->pathname, compmethod);
        }
        return (stream->last_rv = SKSTREAM_ERR_COMPRESS_INVALID);
    }
#undef P_ERR
}


int
skStreamCheckSilkHeader(
    skstream_t         *stream,
    sk_file_format_t    file_format,
    sk_file_version_t   min_version,
    sk_file_version_t   max_version,
    sk_msg_fn_t         errfn)
{
#ifdef TEST_PRINTF_FORMATS
#  define P_ERR printf
#else
#  define P_ERR if (!errfn) { } else errfn
#endif
    sk_file_header_t *hdr = stream->silk_hdr;
    sk_file_format_t fmt = skHeaderGetFileFormat(hdr);
    sk_file_version_t vers = skHeaderGetRecordVersion(hdr);
    char fmt_name[SK_MAX_STRLEN_FILE_FORMAT+1];

    /* get the name of the requested format */
    skFileFormatGetName(fmt_name, sizeof(fmt_name), file_format);

    if (fmt != file_format) {
        P_ERR("File '%s' is not a %s file; format is 0x%02x",
              stream->pathname, fmt_name, fmt);
        return (stream->last_rv = SKSTREAM_ERR_UNSUPPORT_FORMAT);
    }

    if ((vers < min_version) || (vers > max_version)) {
        P_ERR("This version of SiLK cannot process the %s v%u file %s",
              fmt_name, vers, stream->pathname);
        return (stream->last_rv = SKSTREAM_ERR_UNSUPPORT_VERSION);
    }

    return (stream->last_rv = skStreamCheckCompmethod(stream, errfn));
#undef errfn
}


int
skStreamClose(
    skstream_t         *stream)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    if (stream->fp) {
        if (stream->is_pager_active) {
            if (pclose(stream->fp) == -1) {
                stream->errnum = errno;
                if (rv == SKSTREAM_OK) {
                    rv = SKSTREAM_ERR_WRITE;
                }
            }
        } else {
            if (EOF == fclose(stream->fp)) {
                stream->errnum = errno;
                if (rv == SKSTREAM_OK) {
                    rv = SKSTREAM_ERR_WRITE;
                }
            }
        }
    } else if (stream->fd != -1) {
        if (stream->iobuf && stream->io_mode != SK_IO_READ) {
            if (skIOBufFlush(stream->iobuf) == -1) {
                if (stream->is_iobuf_error) {
                    stream->is_iobuf_error = 0;
                    rv = stream->err_info;
                } else {
                    rv = SKSTREAM_ERR_IOBUF;
                }
            }
        }
#if SK_ENABLE_ZLIB
        if (stream->gz) {
            /* Close the gzFile */
            int zerr = gzclose(stream->gz);
            stream->gz = NULL;
            if (zerr != Z_OK) {
                if (zerr == Z_ERRNO) {
                    stream->errnum = errno;
                    rv = SKSTREAM_ERR_WRITE;
                } else {
                    stream->errnum = zerr;
                    rv = SKSTREAM_ERR_ZLIB;
                }
            }
            /* gzclose() closes the file */
            stream->fd = -1;
        } else
#endif /* SK_ENABLE_ZLIB */
        {
            if (stream->is_stdio == 0) {
                if (close(stream->fd) == -1) {
                    stream->errnum = errno;
                    rv = SKSTREAM_ERR_WRITE;
                }
            }
        }
    }

    stream->fd = -1;
    stream->fp = NULL;
    stream->is_closed = 1;

  END:
    return (stream->last_rv = rv);
}


/*
 *  status = skStreamCreate(&out_stream, io_mode, content_type);
 *
 *    Create a stream (skstream_t*) and fill 'out_stream' with the
 *    address of the newly allocated stream.  In addition, bind the
 *    stream to the given 'path', with IO in the specified 'io_mode'.
 *    Return SKSTREAM_OK on success, or an error code on failure.
 */
int
skStreamCreate(
    skstream_t        **new_stream,
    skstream_mode_t     read_write_append,
    skcontent_t         content_type)
{
    if (new_stream == NULL) {
        return SKSTREAM_ERR_NULL_ARGUMENT;
    }

    *new_stream = (skstream_t*)calloc(1, sizeof(skstream_t));
    if (NULL == *new_stream) {
        return SKSTREAM_ERR_ALLOC;
    }

    if (skHeaderCreate(&((*new_stream)->silk_hdr))) {
        free(*new_stream);
        *new_stream = NULL;
        return SKSTREAM_ERR_ALLOC;
    }

    (*new_stream)->io_mode = read_write_append;
    (*new_stream)->content_type = content_type;
    (*new_stream)->fd = -1;

    /* Native format by default, so don't swap */
    (*new_stream)->swapFlag = 0;

    /* Set sensor and flowtype to invalid values */
    (*new_stream)->hdr_sensor = SK_INVALID_SENSOR;
    (*new_stream)->hdr_flowtype = SK_INVALID_FLOWTYPE;

    switch (content_type) {
      case SK_CONTENT_TEXT:
        break;

      case SK_CONTENT_SILK_FLOW:
        (*new_stream)->is_silk_flow = 1;
        /* FALLTHROUGH */

      case SK_CONTENT_SILK:
        (*new_stream)->is_silk = 1;
        /* FALLTHROUGH */

      case SK_CONTENT_OTHERBINARY:
        (*new_stream)->is_binary = 1;
        break;
    }

    return ((*new_stream)->last_rv = SKSTREAM_OK);
}


int
skStreamDestroy(
    skstream_t        **stream)
{
    int rv;

    if ((NULL == stream) || (NULL == *stream)) {
        return SKSTREAM_OK;
    }

    rv = skStreamUnbind(*stream);

    /* Destroy the iobuf */
    if ((*stream)->iobuf) {
        skIOBufDestroy((*stream)->iobuf);
        (*stream)->iobuf = NULL;
    }

    /* Destroy the header */
    skHeaderDestroy(&((*stream)->silk_hdr));

    /* Free the pathname */
    if ((*stream)->pathname) {
        free((*stream)->pathname);
        (*stream)->pathname = NULL;
    }

    free(*stream);
    *stream = NULL;

    return rv;
}


int
skStreamFDOpen(
    skstream_t         *stream,
    int                 file_desc)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckUnopened(stream);
    if (rv) { goto END; }

    if (stream->pathname == NULL) {
        rv = SKSTREAM_ERR_NOT_BOUND;
        goto END;
    }

    if (file_desc == -1) {
        rv = SKSTREAM_ERR_INVALID_INPUT;
        goto END;
    }

    /* Check file modes */
    rv = fcntl(file_desc, F_GETFL, 0);
    if (rv == -1) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_FCNTL_GETFL;
        goto END;
    }
    switch (stream->io_mode) {
      case SK_IO_READ:
        if ((rv & O_ACCMODE) == O_WRONLY) {
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
        break;
      case SK_IO_WRITE:
        if (((rv & O_ACCMODE) == O_RDONLY) || (rv & O_APPEND)) {
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
        break;
      case SK_IO_APPEND:
        if (((rv & O_ACCMODE) != O_RDWR) || !(rv & O_APPEND)) {
            rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
            goto END;
        }
        break;
    }

    /* Check tty status if binary */
    if (stream->is_binary && isatty(file_desc)) {
        rv = SKSTREAM_ERR_ISTERMINAL;
        goto END;
    }

    /* Seek to beginning on append for the header.  Check this after
     * the tty status check, because that is a more useful error
     * message. */
    if ((stream->io_mode == SK_IO_APPEND)
        && (-1 == lseek(file_desc, 0, SEEK_SET)))
    {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_LSEEK;
        goto END;
    }

    stream->fd = file_desc;

    rv = streamPostOpen(stream);
    if (rv) { goto END; }

  END:
    return (stream->last_rv = rv);
}


int
skStreamFlush(
    skstream_t         *stream)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    if (stream->io_mode == SK_IO_READ) {
        /* nothing to do for a reader */
        goto END;
    }

    if (stream->fp) {
        if (EOF == fflush(stream->fp)) {
            stream->errnum = errno;
            rv = SKSTREAM_ERR_WRITE;
        }
    } else if (stream->iobuf) {
        if (skIOBufFlush(stream->iobuf) == -1) {
            if (stream->is_iobuf_error) {
                stream->is_iobuf_error = 0;
                rv = stream->err_info;
            } else {
                rv = SKSTREAM_ERR_IOBUF;
            }
            goto END;
        }
#if SK_ENABLE_ZLIB
    } else if (stream->gz) {
        if (streamGZFlush(stream) == -1) {
            stream->is_iobuf_error = 0;
            rv = stream->err_info;
        }
#endif  /* SK_ENABLE_ZLIB */
    }

  END:
    return (stream->last_rv = rv);
}


/* return the content type */
skcontent_t
skStreamGetContentType(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->content_type;
}


/* return the file descriptor */
int
skStreamGetDescriptor(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->fd;
}


/* return the cached errno value */
int
skStreamGetLastErrno(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->errnum;
}


/* return the cached return value */
ssize_t
skStreamGetLastReturnValue(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->last_rv;
}


/* fill 'value' with the limit implied by the error code */
int
skStreamGetLimit(
    const skstream_t   *stream,
    int                 limit_id,
    int64_t            *value)
{
    sk_file_format_t file_format;
    sk_file_version_t rec_version;
    int rv = SKSTREAM_OK;

    assert(stream);

    if (!stream->is_silk_flow || !stream->silk_hdr) {
        rv = SKSTREAM_ERR_REQUIRE_SILK_FLOW;
        goto END;
    }

    file_format = skHeaderGetFileFormat(stream->silk_hdr);
    rec_version = skHeaderGetRecordVersion(stream->silk_hdr);
    if (UINT8_MAX == file_format) {
        file_format = DEFAULT_FILE_FORMAT;
    }

    switch (limit_id) {
      case SKSTREAM_ERR_PKTS_ZERO:
        /* The record contains a 0 value in the packets field. */
        *value = 1;
        break;

      case SKSTREAM_ERR_STIME_UNDRFLO:
        /* The record's start time is less than the file's start
         * time */
        switch (file_format) {
          case FT_RWAUGMENTED:
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
          case FT_RWAUGWEB:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
          case FT_RWSPLIT:
          case FT_RWWWW:
            *value = stream->hdr_starttime;
            break;
          default:
            *value = 0;
            break;
        }
        break;

      case SKSTREAM_ERR_STIME_OVRFLO:
        /* The record's start time at least an hour greater than the
         * file's start time */
        *value = (int64_t)sktimeCreate(UINT32_MAX, 0);
        switch (file_format) {
          case FT_RWAUGMENTED:
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
          case FT_RWAUGWEB:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
          case FT_RWSPLIT:
          case FT_RWWWW:
            *value = (stream->hdr_starttime
                      + sktimeCreate((MAX_START_TIME - 1), 0));
            break;
          case FT_RWGENERIC:
            switch (rec_version) {
              case 5:
                *value = INT64_MAX;
                break;
            }
            break;
          case FT_RWIPV6:
            switch (rec_version) {
              case 2:
                *value = (stream->hdr_starttime
                          + sktimeCreate((MAX_START_TIME - 1), 0));
                break;
              default:
                *value = INT64_MAX;
                break;
            }
            break;
          case FT_RWIPV6ROUTING:
            *value = INT64_MAX;
            break;
        }
        break;

      case SKSTREAM_ERR_ELPSD_OVRFLO:
          /* The record's elapsed time is greater than space allocated
           * for duration in this file format */
        switch (file_format) {
          case FT_RWAUGMENTED:
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
            if (rec_version <= 4) {
                *value = (MAX_ELAPSED_TIME - 1) * 1000;
            } else {
                *value = (int64_t)UINT32_MAX;
            }
            break;
          case FT_RWAUGWEB:
            if (rec_version <= 4) {
                *value = (MAX_ELAPSED_TIME - 1) * 1000;
            } else {
                *value = (int64_t)MASKARRAY_30;
            }
            break;
          case FT_FLOWCAP:
            *value = UINT16_MAX * 1000;
            break;
          case FT_RWFILTER:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
          case FT_RWSPLIT:
          case FT_RWWWW:
            switch (rec_version) {
              case 1:
              case 2:
                *value = (MAX_ELAPSED_TIME_OLD - 1) * 1000;
                break;
              default:
                *value = (MAX_ELAPSED_TIME - 1) * 1000;
                break;
            }
            break;
          default:
            *value = (int64_t)UINT32_MAX;
            break;
        }
        break;

      case SKSTREAM_ERR_PKTS_OVRFLO:
        /* The record contains more than the number of packets allowed
         * in this file format */
        switch (file_format) {
          case FT_RWAUGMENTED:
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
          case FT_RWAUGWEB:
            switch (rec_version) {
              case 5:
                *value = (int64_t)UINT32_MAX;
                break;
              default:
                *value = MAX_PKTS * PKTS_DIVISOR - 1;
                break;
            }
            break;
          case FT_RWFILTER:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
          case FT_RWSPLIT:
          case FT_RWWWW:
            *value = MAX_PKTS * PKTS_DIVISOR - 1;
            break;
          case FT_FLOWCAP:
            *value = MASKARRAY_24;
            break;
          case FT_RWGENERIC:
          case FT_RWIPV6:
          case FT_RWIPV6ROUTING:
            *value = (int64_t)UINT32_MAX;
            break;
        }
        break;

      case SKSTREAM_ERR_BPP_OVRFLO:
        /* The byte-per-packet value is too large to fit into the
         * space provided by this file format. */
        switch (file_format) {
          case FT_RWAUGMENTED:
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
          case FT_RWAUGWEB:
            switch (rec_version) {
              case 5:
                *value = (int64_t)UINT32_MAX;
                break;
              default:
                *value = MASKARRAY_14;
                break;
            }
            break;
          case FT_RWFILTER:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
          case FT_RWSPLIT:
          case FT_RWWWW:
            *value = MASKARRAY_14;
            break;
          case FT_FLOWCAP:
          case FT_RWGENERIC:
          case FT_RWIPV6:
          case FT_RWIPV6ROUTING:
            *value = (int64_t)UINT32_MAX;
            break;
        }
        break;

      case SKSTREAM_ERR_SNMP_OVRFLO:
        /* The records contains an SNMP value too large to fit into
         * the space allocated in this file format. */
        *value = 0;
        switch (file_format) {
          case FT_RWAUGROUTING:
          case FT_RWAUGSNMPOUT:
          case FT_RWIPV6ROUTING:
            *value = UINT16_MAX;
            break;
          case FT_RWFILTER:
          case FT_RWNOTROUTED:
          case FT_RWROUTED:
            switch (rec_version) {
              case 1:
              case 2:
                *value = UINT8_MAX;
                break;
              default:
                *value = UINT16_MAX;
                break;
            }
            break;
          case FT_RWGENERIC:
            switch (rec_version) {
              case 0:
              case 1:
                *value = UINT8_MAX;
                break;
              default:
                *value = UINT16_MAX;
                break;
            }
            break;
          case FT_FLOWCAP:
            switch (rec_version) {
              case 2:
              case 3:
              case 4:
                *value = UINT8_MAX;
                break;
              default:
                *value = UINT16_MAX;
                break;
            }
            break;
        }
        break;

      case SKSTREAM_ERR_SENSORID_OVRFLO:
        /* The records contains a SensorID too large to fit into the
         * space allocated in this file format. */
        *value = UINT16_MAX;
        switch (file_format) {
          case FT_RWFILTER:
            switch (rec_version) {
              case 1:
                *value = MASKARRAY_06;
                break;
              case 2:
                *value = UINT8_MAX;
                break;
            }
            break;
          case FT_RWGENERIC:
            switch (rec_version) {
              case 0:
              case 1:
                *value = UINT8_MAX;
                break;
            }
            break;
        }
        break;

      default:
        /* unknown limit */
        rv = SKSTREAM_ERR_INVALID_INPUT;
        break;
    }

  END:
    return rv;
}


/* Get the next line from a text file */
int
skStreamGetLine(
    skstream_t         *stream,
    char               *out_buffer,
    size_t              buf_size,
    int                *lines_read)
{
    size_t len;
    int rv = SKSTREAM_OK;

    assert(stream);

    if ( !stream->is_dirty) {
        rv = streamCheckOpen(stream);
        if (rv) { goto END; }

        rv = streamCheckAttributes(stream, SK_IO_READ, SK_CONTENT_TEXT);
        if (rv) { goto END; }

        rv = streamPrepareText(stream);
        if (rv) { goto END; }
    }
#ifndef NDEBUG
    else {
        assert(!stream->is_binary);
        assert(stream->content_type == SK_CONTENT_TEXT);
        assert(stream->io_mode == SK_IO_READ);
        assert(stream->fd != -1);
    }
#endif

    assert(out_buffer && buf_size);
    out_buffer[0] = '\0';

    /* read from the stream until we get a good line */
    for (;;) {
        rv = streamIOBufGetLine(stream, out_buffer, buf_size);
        if (rv != SKSTREAM_OK) {
            if ((rv == SKSTREAM_ERR_LONG_LINE) && lines_read) {
                ++*lines_read;
            }
            break;
        }
        if (lines_read) {
            ++*lines_read;
        }

        /* Terminate line at first comment char */
        if (stream->comment_start) {
            char *cp = strstr(out_buffer, stream->comment_start);
            if (cp) {
                *cp = '\0';
            }
        }

        /* find first non-space character in the line */
        len = strspn(out_buffer, " \t\v\f\r\n");
        if (out_buffer[len] == '\0') {
            /* line contained whitespace only; ignore */
            continue;
        }

        /* got a line, break out of loop */
        break;
    }

  END:
    return (stream->last_rv = rv);
}


/* return the read/write/append mode */
skstream_mode_t
skStreamGetMode(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->io_mode;
}


/* return the name of pager program */
const char *
skStreamGetPager(
    const skstream_t   *stream)
{
    if (stream->is_closed) {
        return NULL;
    } else if (stream->is_pager_active) {
        /* stream is open and pager is in use */
        return stream->pager;
    } else if (stream->fd == -1) {
        /* unopened, return pager we *may* use */
        return stream->pager;
    } else {
        /* stream is open and not using pager */
        return NULL;
    }
}


/* return the name of file associated with the stream */
const char *
skStreamGetPathname(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->pathname;
}


/* return number of SiLK flow records processed */
uint64_t
skStreamGetRecordCount(
    const skstream_t   *stream)
{
    assert(stream);
    if (!stream->is_silk_flow) {
        return ((uint64_t)(-1));
    }
    return stream->rec_count;
}


sk_file_header_t *
skStreamGetSilkHeader(
    const skstream_t   *stream)
{
    if (!stream->is_silk) {
        return NULL;
    }
    return stream->silk_hdr;
}


int
skStreamGetSupportsIPv6(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->supports_ipv6;
}


off_t
skStreamGetUpperBound(
    skstream_t         *stream)
{
    assert(stream);
    assert(stream->fd != -1);

    if (stream->io_mode == SK_IO_READ) {
        return 0;
    }
    if (stream->iobuf) {
        return stream->pre_iobuf_pos + skIOBufTotalUpperBound(stream->iobuf);
    }
    return lseek(stream->fd, 0, SEEK_CUR);
}


int
skStreamInitialize(
    void)
{
    const char *env;

    env = getenv(SILK_ICMP_SPORT_HANDLER_ENVAR);
    if (NULL != env && (0 == strcasecmp(env, "none"))) {
        silk_icmp_nochange = 1;
    }

#ifdef SILK_CLOBBER_ENVAR
    env = getenv(SILK_CLOBBER_ENVAR);
    if (NULL != env && *env && *env != '0') {
        silk_clobber = 1;
    }
#endif

    return 0;
}


int
skStreamIsSeekable(
    const skstream_t   *stream)
{
    assert(stream);
    return stream->is_seekable;
}


int
skStreamIsStdout(
    const skstream_t   *stream)
{
    assert(stream);
    return ((SK_IO_WRITE == stream->io_mode)
            && (NULL != stream->pathname)
            && ((0 == strcmp(stream->pathname, "-"))
                || (0 == strcmp(stream->pathname, "stdout"))));
}


int
skStreamLockFile(
    skstream_t         *stream)
{
    struct flock lock;
    int rv;

    lock.l_start = 0;             /* at SOF */
    lock.l_whence = SEEK_SET;     /* SOF */
    lock.l_len = 0;               /* EOF */

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    /* Don't try to lock anything that is not a real file */
    if ( !stream->is_seekable) {
        goto END;
    }

    /* set the lock type and error code if we fail */
    if (stream->io_mode == SK_IO_READ) {
        lock.l_type = F_RDLCK;
        rv = SKSTREAM_ERR_RLOCK;
    } else {
        lock.l_type = F_WRLCK;
        rv = SKSTREAM_ERR_WLOCK;
    }

    /* get the lock, waiting if we need to */
    if (fcntl(stream->fd, F_SETLKW, &lock) == -1) {
        /* error */
        stream->errnum = errno;
        goto END;
    }

    /* success */
    rv = SKSTREAM_OK;

  END:
    return (stream->last_rv = rv);
}


int
skStreamMakeDirectory(
    skstream_t         *stream)
{
    char dir[PATH_MAX];
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckUnopened(stream);
    if (rv) { goto END; }

    /* Making directory to file only makes sense for writing */
    if (stream->io_mode != SK_IO_WRITE) {
        rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
        goto END;
    }

    if (stream->pathname == NULL) {
        rv = SKSTREAM_ERR_NOT_BOUND;
        goto END;
    }

    if (skDirname_r(dir, stream->pathname, sizeof(dir))) {
        if ( !skDirExists(dir)) {
            rv = skMakeDir(dir);
            if (rv) {
                stream->errnum = errno;
                rv = SKSTREAM_ERR_SYS_MKDIR;
                goto END;
            }
        }
    }

  END:
    return (stream->last_rv = rv);
}


int
skStreamMakeTemp(
    skstream_t         *stream)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckUnopened(stream);
    if (rv) { goto END; }

    /* Temp files only make sense for writing */
    if (stream->io_mode != SK_IO_WRITE) {
        rv = SKSTREAM_ERR_UNSUPPORT_IOMODE;
        goto END;
    }

    if (stream->pathname == NULL) {
        rv = SKSTREAM_ERR_NOT_BOUND;
        goto END;
    }

    /* open file */
    stream->fd = mkstemp(stream->pathname);
    if (stream->fd == -1) {
        rv = SKSTREAM_ERR_SYS_MKSTEMP;
        stream->errnum = errno;
        goto END;
    }

    rv = streamPostOpen(stream);
    if (rv) { goto END; }

  END:
    return (stream->last_rv = rv);
}


int
skStreamOpen(
    skstream_t         *stream)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckUnopened(stream);
    if (rv) { goto END; }

    if (stream->pathname == NULL) {
        rv = SKSTREAM_ERR_NOT_BOUND;
        goto END;
    }

    switch (stream->io_mode) {
      case SK_IO_WRITE:
        rv = streamOpenWrite(stream);
        if (rv) { goto END; }
        break;

      case SK_IO_READ:
        rv = streamOpenRead(stream);
        if (rv) { goto END; }
        break;

      case SK_IO_APPEND:
        rv = streamOpenAppend(stream);
        if (rv) { goto END; }
        break;
    }

    rv = streamPostOpen(stream);
    if (rv) { goto END; }

  END:
    return (stream->last_rv = rv);
}


/* convenience function to create and open a SiLK flow file */
int
skStreamOpenSilkFlow(
    skstream_t        **stream,
    const char         *pathname,
    skstream_mode_t     read_write_append)
{
    int rv;

    /* Allocate and initialize the stream */
    rv = skStreamCreate(stream, read_write_append, SK_CONTENT_SILK_FLOW);
    if (rv) { goto END; }

    rv = skStreamBind(*stream, pathname);
    if (rv) { goto END; }

    rv = skStreamOpen(*stream);
    if (rv) { goto END; }

    switch ((*stream)->io_mode) {
      case SK_IO_WRITE:
        break;

      case SK_IO_READ:
      case SK_IO_APPEND:
        rv = skStreamReadSilkHeader(*stream, NULL);
        if (rv) {
            skStreamClose(*stream);
            goto END;
        }
        break;
    }

  END:
    if (*stream) {
        (*stream)->last_rv = rv;
    }
    return rv;
}


int
skStreamPageOutput(
    skstream_t         *stream,
    const char         *pager)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckModifiable(stream);
    if (rv) { goto END; }

    rv = streamCheckAttributes(stream, SK_IO_WRITE, SK_CONTENT_TEXT);
    if (rv) { goto END; }

    /* get pager from environment if not passed in */
    if (NULL == pager) {
        pager = getenv("SILK_PAGER");
        if (NULL == pager) {
            pager = getenv("PAGER");
        }
    }

    /* a NULL or an empty string pager means do nothing */
    if ((NULL == pager) || ('\0' == pager[0])) {
        if (stream->pager) {
            free(stream->pager);
            stream->pager = NULL;
        }
        goto END;
    }

    if (stream->pager) {
        free(stream->pager);
    }
    stream->pager = strdup(pager);
    if (stream->pager == NULL) {
        rv = SKSTREAM_ERR_ALLOC;
        goto END;
    }

    /* if the stream is open, go ahead and invoke the pager now */
    if (stream->fd != -1) {
        rv = streamPrepareText(stream);
        if (rv) { goto END; }
    }

  END:
    return (stream->last_rv = rv);
}


#if !defined(skStreamPrint)
int
skStreamPrint(
    skstream_t         *stream,
    const char         *format,
    ...)
{
    int rv = SKSTREAM_OK;
    va_list args;

    assert(stream);

    va_start(args, format);

    if ( !stream->fp) {
        rv = streamCheckOpen(stream);
        if (rv) { goto END; }

        rv = streamCheckAttributes(stream, (SK_IO_WRITE | SK_IO_APPEND),
                                   SK_CONTENT_TEXT);
        if (rv) { goto END; }

        rv = streamPrepareText(stream);
        if (rv) { goto END; }
    }
#ifndef NDEBUG
    else {
        assert(!stream->is_binary);
        assert(stream->content_type == SK_CONTENT_TEXT);
        assert(stream->io_mode==SK_IO_WRITE || stream->io_mode==SK_IO_APPEND);
        assert(stream->fd != -1);
    }
#endif  /* NDEBUG */

    if (vfprintf(stream->fp, format, args) == -1) {
        rv = SKSTREAM_ERR_WRITE;
        stream->errnum = errno;
    }

  END:
    va_end(args);
    return (stream->last_rv = rv);
}
#endif /* !defined(skStreamPrint) */


ssize_t
skStreamRead(
    skstream_t         *stream,
    void               *buf,
    size_t              count)
{
    ssize_t saw;

    assert(stream);
    assert(stream->io_mode == SK_IO_READ || stream->io_mode == SK_IO_APPEND);
    assert(stream->fd != -1);

    if (stream->iobuf) {
        saw = skIOBufRead(stream->iobuf, buf, count);
        if (saw >= 0) {
            return (stream->last_rv = saw);
        }
        if (stream->is_iobuf_error) {
            stream->is_iobuf_error = 0;
        } else {
            stream->err_info = SKSTREAM_ERR_IOBUF;
        }
        return (stream->last_rv = saw);
    }
    if (buf == NULL) {
        return (stream->last_rv = streamReadNullBuffer(stream, count));
    }
#if SK_ENABLE_ZLIB
    if (stream->gz != NULL) {
        saw = streamGZRead(stream, buf, count);
        if (saw == -1) {
            stream->is_iobuf_error = 0;
        }
        return (stream->last_rv = saw);
    }
#endif

    saw = skreadn(stream->fd, buf, count);
    if (saw == -1) {
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_READ;
    }
    return (stream->last_rv = saw);
}


void *
skStreamReadToEndOfFile(
    skstream_t         *stream,
    ssize_t            *count)
{
#define READTOEND_BUFSIZE 1024

    uint8_t *buf = NULL;
    uint8_t *bp;
    ssize_t saw;
    ssize_t total = 0;
    size_t bufsize = 0;

    for (;;) {
        if (bufsize < 4 * READTOEND_BUFSIZE) {
            bufsize += READTOEND_BUFSIZE;
        } else {
            bufsize += bufsize >> 1;
        }
        bp = (uint8_t*)realloc(buf, bufsize);
        if (NULL == bp) {
            stream->errnum = errno;
            stream->err_info = SKSTREAM_ERR_ALLOC;
            stream->last_rv = stream->err_info;
            break;
        }
        buf = bp;
        bp += total;

        saw = skStreamRead(stream, bp, (bufsize - total));
        if (-1 == saw) {
            stream->last_rv = saw;
            break;
        }

        total += saw;
        if (saw < (ssize_t)(bufsize - total)) {
            *count = total;
            buf[total] = '\0';
            return buf;
        }
    }

    /* only get here on error */
    if (buf) {
        free(buf);
    }
    return NULL;
}


int
skStreamReadRecord(
    skstream_t         *stream,
    rwGenericRec_V5    *rwrec)
{
#ifndef SK_HAVE_ALIGNED_ACCESS_REQUIRED
    uint8_t ar[SK_MAX_RECORD_SIZE];
#else
    /* force 'ar' to be aligned on an 8byte boundary, since we treat
     * it as an rwRec and need to access the 64bit sTime. */
    union force_align_un {
        uint8_t  fa_ar[SK_MAX_RECORD_SIZE];
        uint64_t fa_u64;
    } force_align;
    uint8_t *ar = force_align.fa_ar;
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */

    ssize_t saw;
    int rv = SKSTREAM_OK;

    if (stream->is_eof) {
        rv = SKSTREAM_ERR_EOF;
        goto END;
    }

    assert(stream);
    assert(stream->io_mode == SK_IO_READ || stream->io_mode == SK_IO_APPEND);
    assert(stream->content_type != SK_CONTENT_TEXT);
    assert(stream->is_binary);
    assert(stream->fd != -1);

    /* label is used by the IPv6 policy to ignore a record */
  NEXT_RECORD:

    /* read the packed record as a byte array */
    if (stream->iobuf) {
        /* avoid function call for the common case */
        saw = skIOBufRead(stream->iobuf, ar, stream->recLen);
    } else {
        saw = skStreamRead(stream, ar, stream->recLen);
    }
    if (saw != (ssize_t)stream->recLen) {
        /* EOF or error */
        stream->is_eof = 1;

        if (saw == 0) {
            /* 0 means clean record boundary; simple EOF */
            rv = SKSTREAM_ERR_EOF;
        } else if (saw == -1) {
            /* error */
            if (stream->iobuf) {
                rv = SKSTREAM_ERR_IOBUF;
            } else {
                rv = -1;
            }
        } else {
            /* short read */
            stream->errobj.num = saw;
            rv = SKSTREAM_ERR_READ_SHORT;
        }
        goto END;
    }

    /* clear the caller's record */
    RWREC_CLEAR(rwrec);

    /* convert the byte array to an rwRec in native byte order */
#if SK_ENABLE_IPV6
    stream->rwUnpackFn(stream, rwrec, ar);
#else
    if (stream->rwUnpackFn(stream, rwrec, ar) == SKSTREAM_ERR_UNSUPPORT_IPV6) {
        goto NEXT_RECORD;
    }
#endif

    /* Handle incorrectly encoded ICMP Type/Code unless the
     * SILK_ICMP_SPORT_HANDLER environment variable is set to none. */
    if (rwRecIsICMP(rwrec)
        && rwRecGetSPort(rwrec) != 0
        && rwRecGetDPort(rwrec) == 0
        && !silk_icmp_nochange)
    {
        /*
         *  There are two ways for the ICMP Type/Code to appear in
         *  "sPort" instead of in "dPort".
         *
         *  (1) The flow was an IPFIX bi-flow record read prior to
         *  SiLK-3.4.0 where the sPort and dPort of the second record
         *  were reversed when they should not have been.  Here, the
         *  sPort contains ((type<<8)|code).
         *
         *  (2) The flow was a NetFlowV5 record read from a buggy
         *  Cisco router and read prior to SiLK-0.8.0.  Here, the
         *  sPort contains ((code<<8)|type).
         *
         *  The following assumes buggy ICMP flow records were created
         *  from IPFIX sources unless they were created prior to SiLK
         *  1.0 and appear in certain file formats more closely
         *  associated with NetFlowV5.
         *
         *  Prior to SiLK-3.4.0, the buggy ICMP record would propagate
         *  through the tool suite and be written to binary output
         *  files.  As of 3.4.0, we modify the record on read.
         */
        if (skHeaderGetFileVersion(stream->silk_hdr) >= 16) {
            /* File created by SiLK 1.0 or later; most likely the
             * buggy value originated from an IPFIX source. */
            rwRecSetDPort(rwrec, rwRecGetSPort(rwrec));
        } else {
            switch(skHeaderGetFileFormat(stream->silk_hdr)) {
              case FT_RWFILTER:
              case FT_RWNOTROUTED:
              case FT_RWROUTED:
              case FT_RWSPLIT:
              case FT_RWWWW:
                /* Most likely from a PDU source */
                rwRecSetDPort(rwrec, BSWAP16(rwRecGetSPort(rwrec)));
                break;
              default:
                /* Assume it is from an IPFIX source */
                rwRecSetDPort(rwrec, rwRecGetSPort(rwrec));
                break;
            }
        }
        rwRecSetSPort(rwrec, 0);
    }

    /* Write to the copy-input stream */
    if (stream->copyInputFD) {
        skStreamWriteRecord(stream->copyInputFD, rwrec);
    }

    /* got a record */
    ++stream->rec_count;

#if SK_ENABLE_IPV6
    switch (stream->v6policy) {
      case SK_IPV6POLICY_MIX:
        break;

      case SK_IPV6POLICY_IGNORE:
        if (rwRecIsIPv6(rwrec)) {
            goto NEXT_RECORD;
        }
        break;

      case SK_IPV6POLICY_ASV4:
        if (rwRecIsIPv6(rwrec)) {
            if (rwRecConvertToIPv4(rwrec)) {
                goto NEXT_RECORD;
            }
        }
        break;

      case SK_IPV6POLICY_FORCE:
        if (!rwRecIsIPv6(rwrec)) {
            rwRecConvertToIPv6(rwrec);
        }
        break;

      case SK_IPV6POLICY_ONLY:
        if (!rwRecIsIPv6(rwrec)) {
            goto NEXT_RECORD;
        }
        break;
    }
#endif /* SK_ENABLE_IPV6 */

  END:
    return (stream->last_rv = rv);
}


int
skStreamReadSilkHeader(
    skstream_t         *stream,
    sk_file_header_t  **hdr)
{
    int rv = SKSTREAM_OK;

    STREAM_RETURN_IF_NULL(stream);

    if (!stream->is_dirty) {
        rv = skStreamReadSilkHeaderStart(stream);
        if (rv) { goto END; }
    } else if (!stream->is_silk) {
        rv = SKSTREAM_ERR_UNSUPPORT_CONTENT;
        goto END;
    }

    if (hdr) {
        *hdr = stream->silk_hdr;
    }

    /* only read the header one time */
    if (stream->have_hdr) {
        goto END;
    }

    rv = skHeaderReadEntries(stream, stream->silk_hdr);
    if (rv) { goto END; }

    skHeaderSetLock(stream->silk_hdr, SKHDR_LOCK_FIXED);

    if (stream->is_silk_flow) {
        /* swap bytes? */
        stream->swapFlag = !skHeaderIsNativeByteOrder(stream->silk_hdr);

        /* Cache values from the packedfile header */
        streamCacheHeader(stream);

        /* Set pointers to the PackFn and UnpackFn functions for this
         * file format. */
        rv = streamPrepareFormat(stream);
        if (rv) { goto END; }

        assert(stream->recLen > 0);
        assert(stream->recLen <= SK_MAX_RECORD_SIZE);
    }

    /* Move to end of file is stream was open for append */
    if (stream->io_mode == SK_IO_APPEND) {
        if (-1 == lseek(stream->fd, 0, SEEK_END)) {
            stream->errnum = errno;
            rv = SKSTREAM_ERR_SYS_LSEEK;
            goto END;
        }
    }

    /* we have the complete header */
    stream->have_hdr = 1;

    rv = streamIOBufCreate(stream);
    if (rv) { goto END; }

  END:
    return (stream->last_rv = rv);
}


int
skStreamReadSilkHeaderStart(
    skstream_t         *stream)
{
    int rv;
    int flows_required;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    if (stream->is_dirty) {
        rv = SKSTREAM_ERR_PREV_DATA;
        goto END;
    }

    rv = streamCheckAttributes(stream, (SK_IO_READ | SK_IO_APPEND),
                               (SK_CONTENT_SILK | SK_CONTENT_SILK_FLOW));
    if (rv) { goto END; }

    stream->is_dirty = 1;

    rv = skHeaderReadStart(stream, stream->silk_hdr);
    if (rv) { goto END; }

    /* check whether this stream contains flow data */
    flows_required = stream->is_silk_flow;
    STREAM_SET_IS_SILK_FLOW(stream);
    if (flows_required && !stream->is_silk_flow) {
        rv = SKSTREAM_ERR_REQUIRE_SILK_FLOW;
        goto END;
    }

    skHeaderSetLock(stream->silk_hdr, SKHDR_LOCK_ENTRY_OK);

  END:
    return (stream->last_rv = rv);
}


int
skStreamSetCommentStart(
    skstream_t         *stream,
    const char         *comment_start)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckAttributes(stream, SK_IO_READ, SK_CONTENT_TEXT);
    if (rv) { goto END; }

    /* clear existing value */
    if (stream->comment_start) {
        free(stream->comment_start);
    }

    /* set to new value */
    if (comment_start == NULL) {
        stream->comment_start = NULL;
    } else {
        stream->comment_start = strdup(comment_start);
        if (stream->comment_start == NULL) {
            rv = SKSTREAM_ERR_ALLOC;
            goto END;
        }
    }

  END:
    return (stream->last_rv = rv);
}


int
skStreamSetCopyInput(
    skstream_t         *read_stream,
    skstream_t         *write_stream)
{
    assert(read_stream);
    assert(read_stream->is_silk_flow);

    if (write_stream == NULL) {
        return (read_stream->last_rv = SKSTREAM_ERR_NULL_ARGUMENT);
    }
    if (read_stream->copyInputFD) {
        return (read_stream->last_rv = SKSTREAM_ERR_PREV_COPYINPUT);
    }
    if (read_stream->rec_count) {
        return (read_stream->last_rv = SKSTREAM_ERR_PREV_DATA);
    }

    read_stream->copyInputFD = write_stream;
    return (read_stream->last_rv = SKSTREAM_OK);
}


int
skStreamSetIPv6Policy(
    skstream_t         *stream,
    sk_ipv6policy_t     policy)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckAttributes(stream, 0xFF,
                               (SK_CONTENT_SILK | SK_CONTENT_SILK_FLOW));
    if (rv) { goto END; }

    stream->v6policy = policy;

  END:
    return (stream->last_rv = rv);
}


int
skStreamSetUnbuffered(
    skstream_t         *stream)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckUnopened(stream);
    if (rv) { goto END; }

    stream->is_unbuffered = 1;

  END:
    return (stream->last_rv = rv);
}


int
skStreamSkipRecords(
    skstream_t         *stream,
    size_t              skip_count,
    size_t             *records_skipped)
{
    size_t local_records_skipped;
    ssize_t saw;
    ssize_t tmp;
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    if (stream->is_eof) {
        rv = SKSTREAM_ERR_EOF;
        goto END;
    }

    if (NULL == records_skipped) {
        records_skipped = &local_records_skipped;
    }
    *records_skipped = 0;

    /* when some other stream is expecting to see the records, we need
     * to read each record individually */
    if (stream->copyInputFD) {
        size_t skipped = skip_count;
        rwRec rec;

        while ((skipped > 0)
               && ((rv = skStreamReadRecord(stream, &rec)) == SKSTREAM_OK))
        {
            --skipped;
        }
        *records_skipped = skip_count - skipped;
        goto END;
    }

    if (!stream->iobuf) {
        rv = streamSkipRecordsNonIOBuf(stream, skip_count, records_skipped);
        goto END;
    }

    while (skip_count > 0) {
        if (skip_count > (size_t)SSIZE_MAX / stream->recLen) {
            tmp = SSIZE_MAX;
        } else {
            tmp = stream->recLen * skip_count;
        }

        /* read the bytes and check for error or short reads */
        saw = skIOBufRead(stream->iobuf, NULL, tmp);
        if (saw != tmp) {
            /* Either error or an incomplete read--assume end of file */
            stream->is_eof = 1;
            if (saw == -1) {
                /* error */
                rv = SKSTREAM_ERR_IOBUF;
                goto END;
            }
        }

        /* compute the number of records we actually read, update
         * counters, and check for any partially read records. */
        tmp = (saw / stream->recLen);
        stream->rec_count += tmp;
        skip_count -= tmp;
        saw -= tmp * stream->recLen;
        *records_skipped += tmp;

        if (saw != 0) {
            stream->errobj.num = saw;
            rv = SKSTREAM_ERR_READ_SHORT;
            goto END;
        }
        if (stream->is_eof) {
            rv = SKSTREAM_ERR_EOF;
            goto END;
        }
    }

    rv = SKSTREAM_OK;

  END:
    return (stream->last_rv = rv);
}


void
skStreamTeardown(
    void)
{
    /* nothing to do */
}


off_t
skStreamTell(
    skstream_t         *stream)
{
    off_t pos;
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) {
        stream->err_info = rv;
        return (stream->last_rv = -1);
    }

    pos = lseek(stream->fd, 0, SEEK_CUR);
    if (pos == (off_t)-1) {
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_SYS_LSEEK;
    }

    return (stream->last_rv = pos);
}


int
skStreamTruncate(
    skstream_t         *stream,
    off_t               length)
{
    int rv;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    rv = streamCheckAttributes(stream, (SK_IO_WRITE | SK_IO_APPEND),
                               (SK_CONTENT_SILK | SK_CONTENT_SILK_FLOW
                                | SK_CONTENT_OTHERBINARY));
    if (rv) { goto END; }

    if ( !stream->is_seekable) {
        rv = SKSTREAM_ERR_NOT_SEEKABLE;
        goto END;
    }

    /* attempt to truncate the file even if flush fails */
    rv = skStreamFlush(stream);
    if (ftruncate(stream->fd, length) == -1) {
        stream->errnum = errno;
        rv = SKSTREAM_ERR_SYS_FTRUNCATE;
    }

  END:
    return (stream->last_rv = rv);
}


int
skStreamUnbind(
    skstream_t         *stream)
{
    int rv = SKSTREAM_OK;

    if (!stream) {
        return rv;
    }
    if (stream->fd != -1) {
        rv = skStreamClose(stream);
    }

    if (stream->comment_start) {
        free(stream->comment_start);
        stream->comment_start = NULL;
    }
    if (stream->pager) {
        free(stream->pager);
        stream->pager = NULL;
    }
    if (stream->pathname) {
        free(stream->pathname);
        stream->pathname = NULL;
    }

    return (stream->last_rv = rv);
}


ssize_t
skStreamWrite(
    skstream_t         *stream,
    const void         *buf,
    size_t              count)
{
    ssize_t written;

    assert(stream);
    assert(stream->io_mode == SK_IO_WRITE || stream->io_mode == SK_IO_APPEND);
    assert(stream->is_binary);
    assert(stream->fd != -1);
    assert(buf);

    if (stream->iobuf) {
        written = skIOBufWrite(stream->iobuf, buf, count);
        if (written >= 0) {
            return (stream->last_rv = written);
        }
        if (stream->is_iobuf_error) {
            stream->is_iobuf_error = 0;
        } else {
            stream->err_info = SKSTREAM_ERR_IOBUF;
        }
        return (stream->last_rv = written);
    }
#if SK_ENABLE_ZLIB
    if (stream->gz != NULL) {
        written = streamGZWrite(stream, buf, count);
        if (written == -1) {
            stream->is_iobuf_error = 0;
        }
        return (stream->last_rv = written);
    }
#endif  /* SK_ENABLE_ZLIB */

    written = skwriten(stream->fd, buf, count);
    if (written == -1) {
        stream->errnum = errno;
        stream->err_info = SKSTREAM_ERR_WRITE;
    }
    return (stream->last_rv = written);
}


int
skStreamWriteRecord(
    skstream_t             *stream,
    const rwGenericRec_V5  *rwrec)
{
#ifndef SK_HAVE_ALIGNED_ACCESS_REQUIRED
    uint8_t ar[SK_MAX_RECORD_SIZE];
#else
    /* force 'ar' to be aligned on an 8byte boundary, since we treat
     * it as an rwRec and need to access the 64bit sTime. */
    union force_align_un {
        uint8_t  fa_ar[SK_MAX_RECORD_SIZE];
        uint64_t fa_u64;
    } force_align;
    uint8_t *ar = force_align.fa_ar;
#endif  /* SK_HAVE_ALIGNED_ACCESS_REQUIRED */

#if SK_ENABLE_IPV6
    rwRec rec_copy;
#endif

    int rv;
    const rwRec *rp = rwrec;

    assert(stream);
    assert(stream->io_mode == SK_IO_WRITE || stream->io_mode == SK_IO_APPEND);
    assert(stream->is_silk_flow);
    assert(stream->fd != -1);

    if (!stream->is_dirty) {
        rv = skStreamWriteSilkHeader(stream);
        if (rv) {
            return (stream->last_rv = rv);
        }
    }

#if SK_ENABLE_IPV6
    if (rwRecIsIPv6(rp)) {
        switch (stream->v6policy) {
          case SK_IPV6POLICY_MIX:
          case SK_IPV6POLICY_FORCE:
          case SK_IPV6POLICY_ONLY:
            /* flow already IPv6; verify that file format supports it */
            if (stream->supports_ipv6 == 0) {
                return (stream->last_rv = SKSTREAM_ERR_UNSUPPORT_IPV6);
            }
            break;

          case SK_IPV6POLICY_IGNORE:
            /* we're ignoring IPv6, return */
            return (stream->last_rv = SKSTREAM_OK);

          case SK_IPV6POLICY_ASV4:
            /* attempt to convert IPv6 flow to v4 */
            memcpy(&rec_copy, rp, sizeof(rwRec));
            if (rwRecConvertToIPv4(&rec_copy)) {
                return (stream->last_rv = SKSTREAM_OK);
            }
            rp = &rec_copy;
            break;
        }
    } else {
        /* flow is IPv4 */
        switch (stream->v6policy) {
          case SK_IPV6POLICY_MIX:
          case SK_IPV6POLICY_IGNORE:
          case SK_IPV6POLICY_ASV4:
            /* flow is already IPv4; all file formats supported */
            break;

          case SK_IPV6POLICY_ONLY:
            /* we're ignoring IPv4 flows; return */
            return (stream->last_rv = SKSTREAM_OK);

          case SK_IPV6POLICY_FORCE:
            /* must convert flow to IPv6, but first verify that file
             * format supports IPv6 */
            if (stream->supports_ipv6 == 0) {
                return (stream->last_rv = SKSTREAM_ERR_UNSUPPORT_IPV6);
            }
            /* convert */
            memcpy(&rec_copy, rp, sizeof(rwRec));
            rp = &rec_copy;
            rwRecConvertToIPv6(&rec_copy);
            break;
        }
    }
#endif /* SK_ENABLE_IPV6 */

    /* Convert the record into a byte array in the appropriate byte order */
    rv = stream->rwPackFn(stream, rp, ar);
    if (rv != SKSTREAM_OK) {
        stream->errobj.rec = rwrec;
        return (stream->last_rv = rv);
    }

    /* write the record */
    if (stream->iobuf) {
        if (skIOBufWrite(stream->iobuf, ar, stream->recLen)
            == (ssize_t)stream->recLen)
        {
            ++stream->rec_count;
            return (stream->last_rv = SKSTREAM_OK);
        } else if (stream->is_iobuf_error) {
            stream->is_iobuf_error = 0;
        } else {
            stream->err_info = SKSTREAM_ERR_IOBUF;
        }
    } else {
        if (skStreamWrite(stream, ar, stream->recLen)
            == (ssize_t)stream->recLen)
        {
            ++stream->rec_count;
            return (stream->last_rv = SKSTREAM_OK);
        }
    }

    return (stream->last_rv = -1);
}


int
skStreamWriteSilkHeader(
    skstream_t         *stream)
{
    int rv;
    int flows_required;

    STREAM_RETURN_IF_NULL(stream);

    rv = streamCheckOpen(stream);
    if (rv) { goto END; }

    if (stream->is_dirty) {
        rv = SKSTREAM_ERR_PREV_DATA;
        goto END;
    }

    rv = streamCheckAttributes(stream, SK_IO_WRITE,
                               (SK_CONTENT_SILK | SK_CONTENT_SILK_FLOW));
    if (rv) { goto END; }

    if (skHeaderGetFileFormat(stream->silk_hdr) == UINT8_MAX) {
        rv = skHeaderSetFileFormat(stream->silk_hdr, DEFAULT_FILE_FORMAT);
        if (rv) { goto END; }
    }

    /* unless a specific compression method was specified, do not use
     * compression when writing to a non-seekable destination */
    switch (skHeaderGetCompressionMethod(stream->silk_hdr)) {
      case SK_COMPMETHOD_DEFAULT:
        if (!stream->is_seekable && !stream->is_mpi) {
            rv = skHeaderSetCompressionMethod(stream->silk_hdr,
                                              SK_COMPMETHOD_NONE);
        } else {
            rv = skHeaderSetCompressionMethod(stream->silk_hdr,
                                              skCompMethodGetDefault());
        }
        if (rv) { goto END; }
        break;
      case SK_COMPMETHOD_BEST:
        if (!stream->is_seekable && !stream->is_mpi) {
            rv = skHeaderSetCompressionMethod(stream->silk_hdr,
                                              SK_COMPMETHOD_NONE);
        } else {
            rv = skHeaderSetCompressionMethod(stream->silk_hdr,
                                              skCompMethodGetBest());
        }
        if (rv) { goto END; }
        break;
      default:
        break;
    }

    /* check whether this stream contains flow data */
    flows_required = stream->is_silk_flow;
    STREAM_SET_IS_SILK_FLOW(stream);
    if (flows_required && !stream->is_silk_flow) {
        rv = SKSTREAM_ERR_REQUIRE_SILK_FLOW;
        goto END;
    }

    if (stream->is_silk_flow) {
        /* handle the case where a specific record type has not yet
         * been specified. */
        if (skHeaderGetFileFormat(stream->silk_hdr) == UINT8_MAX) {
            rv = skHeaderSetFileFormat(stream->silk_hdr, DEFAULT_FILE_FORMAT);
            if (rv) { goto END; }
        }

        /* Set the file version if it is "ANY", and set pointers to
         * the PackFn and UnpackFn functions for this file format. */
        rv = streamPrepareFormat(stream);
        if (rv) { goto END; }

        assert(stream->recLen > 0);
        assert(stream->recLen <= SK_MAX_RECORD_SIZE);

        /* Set the swapFlag */
        stream->swapFlag = !skHeaderIsNativeByteOrder(stream->silk_hdr);

        /* Cache values from the packedfile header */
        streamCacheHeader(stream);
    }

    stream->is_dirty = 1;
    skHeaderSetLock(stream->silk_hdr, SKHDR_LOCK_FIXED);

    if ( !stream->is_mpi) {
        rv = skHeaderWrite(stream, stream->silk_hdr);
        if (rv) { goto END; }
    }

    rv = streamIOBufCreate(stream);
    if (rv) { goto END; }

  END:
    return (stream->last_rv = rv);
}


/*
 *    Though not functions on skstream_t, these are used heavily by
 *    the code. Define them here and hope the compiler inlines them.
 */

/* Read count bytes from a file descriptor into buf */
ssize_t
skreadn(
    int                 fd,
    void               *buf,
    size_t              count)
{
    ssize_t rv;
    size_t  left = count;

    while (left) {
        rv = read(fd, buf, ((left < INT32_MAX) ? left : INT32_MAX));
        if (rv == -1) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rv == 0) {
            break;
        }
        left -= rv;
        buf = ((uint8_t *)buf) + rv;
    }
    return (count - left);
}

/* Read count bytes from buf to a file descriptor */
ssize_t
skwriten(
    int                 fd,
    const void         *buf,
    size_t              count)
{
    ssize_t rv;
    size_t  left = count;

    while (left) {
        rv = write(fd, buf, ((left < INT32_MAX) ? left : INT32_MAX));
        if (rv == -1) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (rv == 0) {
            break;
        }
        left -= rv;
        buf = ((const uint8_t *)buf) + rv;
    }
    return (count - left);
}


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
