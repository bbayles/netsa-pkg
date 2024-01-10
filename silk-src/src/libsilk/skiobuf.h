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
#ifndef _SKIOBUF_H
#define _SKIOBUF_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKIOBUF_H, "$SiLK: skiobuf.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

/*
**  skiobuf.h
**
**  Routines for buffered file io.
**
*/

#if SK_ENABLE_ZLIB
#include <zlib.h>
#endif


/**
 *    The default uncompressed block size.
 */
#define SKIOBUF_DEFAULT_BLOCKSIZE SKSTREAM_DEFAULT_BLOCKSIZE


/**
 *    The maximum compressed or uncompressed block size.
 */
#define SKIOBUF_MAX_BLOCKSIZE 0x100000 /* One megabyte */


/**
 *    The default record size.  A single record is guaranteed not to
 *    span multiple blocks.
 */
#define SKIOBUF_DEFAULT_RECORDSIZE 1


/**
 *    The type of IO buffer objects
 */
typedef struct sk_iobuf_st sk_iobuf_t;


/*
 *    skIOBuf can wrap an abstract file descriptor 'fd' if it
 *    implements some of the following functions.  A reading skIOBuf
 *    requires the skio_read_fn_t; a writing skIOBuf requires the
 *    skio_write_fn_t.
 */

/**
 *    Implements a read(2)-like call: skIOBuf is requesting that the
 *    'fd' add 'count' bytes of data into 'dest' for input, returning
 *    the number of bytes actually added.  Should return a number less
 *    than count for a short read, -1 for an error.
 */
typedef ssize_t
(*skio_read_fn_t)(
    void           *fd,
    void           *dest,
    size_t          count);

/**
 *    Implements a write(2)-like call: skIOBuf is requesting that the
 *    'fd' accept 'count' bytes of data from 'src' for output,
 *    returning the number of bytes actually accepted.  Should return
 *    a number less than count for a short write (is this even
 *    meaningful?), -1 for an error.
 */
typedef ssize_t
(*skio_write_fn_t)(
    void           *fd,
    const void     *src,
    size_t          count);

/**
 *    Implements an lseek(2)-like call: skIOBuf is requesting that the
 *    read pointer be positioned relative to 'whence' by 'offset'
 *    bytes, returning the new offset of the read pointer.  'whence'
 *    can be SEEK_SET, SEEK_CUR, or SEEK_END.  Returns (off_t)(-1) on
 *    error.  If seek cannot work on a particular fd because it is not
 *    a seekable file, set errno to ESPIPE.
 */
typedef off_t
(*skio_seek_fn_t)(
    void           *fd,
    off_t           offset,
    int             whence);

/**
 *    Implements an fflush(3)-like call: skIOBuf is requesting that
 *    the 'fd' syncronize its output buffers with the physical media.
 *    Returns 0 on success, or -1 on error.  This function may be
 *    NULL.
 */
typedef int (*skio_flush_fn_t)(
    void           *fd);

/**
 *    Implements a strerror(3)-like call: skIOBuf is requesting a
 *    human-readable error message given the error code 'fd_errno'.
 */
typedef const char *
(*skio_strerror_fn_t)(
    void           *fd,
    int             fd_errno);

/**
 *    skIOBuf is requesting that the 'fd' deallocate itself.
 */
typedef void
(*skio_free_fn_t)(
    void           *fd);


/**
 *    All supported operations on an abstract file descriptor.  Either
 *    'read' or 'write' must be specified.
 */
typedef struct skio_abstract_st {
    skio_read_fn_t      read;
    skio_write_fn_t     write;
    skio_seek_fn_t      seek;
    skio_flush_fn_t     flush;
    skio_free_fn_t      free_fd;
    skio_strerror_fn_t  strerror;
} skio_abstract_t;


/**
 *    Creates a new IO buffer for either reading or writing according
 *    to 'mode'.  A 'mode' of SK_IO_APPEND creates a writing IO
 *    buffer.
 *
 *    Returns the new IO buffer or NULL on allocation error.
 */
sk_iobuf_t *
skIOBufCreate(
    skstream_mode_t     mode);


/**
 *    Destroys the IO buffer 'iobuf'.  If the IO buffer is a writer,
 *    the buffer will be flushed before destruction.  Does nothing
 *    when 'iobuf' is NULL.
 */
void
skIOBufDestroy(
    sk_iobuf_t         *iobuf);


/**
 *    Binds the file descriptor 'fd' to the IO buffer 'iobuf'.
 *
 *    If the IO buffer is a reader, any data read from the stream and
 *    held in the IO buffer is lost.
 *
 *    If the IO buffer is a writer and is already associated with a
 *    file descriptor, the buffer will be flushed before binding.
 *
 *    Binding a file descriptor resets the write/read count of the IO
 *    buffer.  'compmethod' is a valid compression method from
 *    silk_files.h.
 *
 *    Returns 0 on success, -1 on failure.
 */
int
skIOBufBind(
    sk_iobuf_t         *iobuf,
    int                 fd,
    sk_compmethod_t     compmethod);


/**
 *    Binds the abstract file descriptor 'fd' to the IO buffer 'iobuf'.
 *
 *    If the IO buffer is a reader, any data read from the stream and
 *    held in the IO buffer is lost.
 *
 *    If the IO buffer is a writer and is already associated with a
 *    file descriptor, the buffer will be flushed before binding.
 *
 *    Binding a file descriptor resets the write/read count of the IO
 *    buffer.  'compmethod' is a valid compression method from
 *    silk_files.h.  'fd_ops' is a pointer to a struct of file
 *    operations on the abstract file descriptor 'fd'.
 */
int
skIOBufBindAbstract(
    sk_iobuf_t         *iobuf,
    void               *fd,
    sk_compmethod_t     compmethod,
    skio_abstract_t    *fd_ops);


/**
 *    Reads 'count' uncompressed bytes into 'data' from the IO buffer
 *    'iobuf'.  When 'data' is NULL, moves the read location 'count'
 *    bytes forward in the stream and that data is lost.
 *
 *    Returns the number of uncompressed bytes read/skipped on
 *    success.  The return value is always 'count' if the stream
 *    contained at least that number of bytes.  If the return value is
 *    a positive number less than 'count', the IO buffer was only able
 *    to read that number of bytes before reaching the end of the
 *    stream.  Returns 0 when there is no more data in the stream.
 *    Returns -1 on failure.
 */
ssize_t
skIOBufRead(
    sk_iobuf_t         *iobuf,
    void               *data,
    size_t              count);


/**
 *    Copies 'count' bytes from 'data' back into the read buffer of
 *    the IO buffer 'iobuf' so those bytes will be returned by the
 *    next call to skIOBufRead().
 *
 *    Adjusts the IO buffer's total read byte count by 'adjust_total'
 *    bytes.  'adjust_total' should 0 when returning bytes from a
 *    previous skIOBufRead().
 *
 *    Returns 'count' if the call was successful.  Returns -1 if
 *    'iobuf' has not been bound, if 'iobuf' is not a reader, if the
 *    'data' parameter is NULL, or on allocation failure.
 *
 *    Any other return value indicates the 'iobuf' does not have space
 *    for 'count' bytes and that 'iobuf' is unchanged.  The return
 *    value is the number of bytes 'iobuf' has available for unget.
 */
ssize_t
skIOBufUnget(
    sk_iobuf_t         *iobuf,
    const void         *data,
    size_t              count,
    off_t               adjust_total);


/**
 *    Reads no more than 'count' uncompressed bytes into 'data' from
 *    the IO buffer 'iobuf', stopping at the first occurrence of the
 *    character 'c' in the stream and including that character in
 *    'data'.  The 'data' parameter may be NULL.
 *
 *    Return values are identical to those for skIOBufRead().
 */
ssize_t
skIOBufReadToChar(
    sk_iobuf_t         *iobuf,
    void               *data,
    size_t              count,
    int                 c);


/**
 *    Writes 'count' uncompressed bytes from 'data' into the IO buffer
 *    'iobuf'.
 *
 *    Returns the number of uncompressed bytes written on success, -1
 *    on failure.  This function will never return a number of bytes
 *    less than 'count'.
 */
ssize_t
skIOBufWrite(
    sk_iobuf_t         *iobuf,
    const void         *data,
    size_t              count);


/**
 *    Flushes the IO buffer writer 'iobuf'.  This does not close the
 *    buffer or the underlying file descriptor.
 *
 *    Returns the number of compressed bytes written to the underlying
 *    file descriptor since it was bound to the IO buffer on success.
 *
 *    Returns -1 on failure on when invoked on a IO buffer created for
 *    reading.
 */
off_t
skIOBufFlush(
    sk_iobuf_t         *iobuf);


/**
 *    Returns the compressed number of bytes that have been actually
 *    been read/written from/to the underlying file descriptor.
 *    Returns -1 on error.
 */
off_t
skIOBufTotal(
    sk_iobuf_t         *iobuf);


/**
 *    Returns an upper bound on the number of compressed bytes that
 *    would be written to the underlying file descriptor since the
 *    binding of the buffer if the buffer were flushed.  Returns -1 on
 *    error.
 */
off_t
skIOBufTotalUpperBound(
    sk_iobuf_t         *iobuf);


/**
 *     Sets the block size for the IO buffer.  This function can only
 *     be called immediately after creation or binding of the IO
 *     buffer.  Returns 0 on success, -1 on error.
 */
int
skIOBufSetBlockSize(
    sk_iobuf_t         *iobuf,
    uint32_t            size);


/**
 *     Returns the maximum possible compressed block size.
 */
uint32_t
skIOBufUpperCompBlockSize(
    sk_iobuf_t         *iobuf);


/**
 *     Sets the record size for the IO buffer.  This function can only
 *     be called immediately after creation or binding of the IO
 *     buffer.  Returns 0 on success, -1 on error.
 */
int
skIOBufSetRecordSize(
    sk_iobuf_t         *iobuf,
    uint32_t            size);


/**
 *    Returns a string representing the error state of the IO buffer
 *    'buf'.  This is a static string similar to that used by
 *    strerror.  This function also resets the error state of the IO
 *    buffer.
 */
const char *
skIOBufStrError(
    sk_iobuf_t         *iobuf);

#ifdef __cplusplus
}
#endif
#endif /* _SKIOBUF_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
