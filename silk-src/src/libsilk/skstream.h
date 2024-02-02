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
**  skstream.h
**
**    An interface around file descriptors, which allows for buffered
**    reading and writing, as well as compression.
**
*/
#ifndef _SKSTREAM_H
#define _SKSTREAM_H
#ifdef __cplusplus
extern "C" {
#endif

#include <silk/silk.h>

RCSIDENTVAR(rcsID_SKSTREAM_H, "$SiLK: skstream.h b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/silk_types.h>
#include <silk/silk_files.h>
#include <silk/skheader.h>

/**
 *  @file
 *
 *    An interface around file descriptors, which allows for buffered
 *    reading and writing, as well as compression.
 *
 *    This file is part of libsilk.
 */


/**
 * Default (uncompressed) block size used when writing/reading: 64k
 */
#define SKSTREAM_DEFAULT_BLOCKSIZE  0x10000


/*
 *    skstream_t, skstream_mode_t, skcontent_t are defined in
 *    silk_types.h.
 */


/**
 *    Return values that most skStream*() functions return
 */
typedef enum {
    /** The last command was completed successfully. */
    SKSTREAM_OK = 0,

    /* The following often represent programmer errors */

    /** Memory could not be allocated. */
    SKSTREAM_ERR_ALLOC = -64,

    /** Attempt to operate on a file that is already closed.  Once
     * closed, a stream can only be destroyed; re-opening is not (yet)
     * supported. */
    SKSTREAM_ERR_CLOSED = -65,

    /** An argument to a function is invalid: passing skStreamFDOpen()
     * a value of -1, passing too long a pathname ti skStreamBind(),
     * using an supported SiLK file format. */
    SKSTREAM_ERR_INVALID_INPUT = -66,

    /** Attempt to open a stream that is not bound to a pathname. */
    SKSTREAM_ERR_NOT_BOUND = -67,

    /** Attempt to read or write from a stream that has not yet been
     * opened. */
    SKSTREAM_ERR_NOT_OPEN = -68,

    /** An argument to the function is NULL or empty */
    SKSTREAM_ERR_NULL_ARGUMENT = -69,

    /** The stream is already bound to a pathname. */
    SKSTREAM_ERR_PREV_BOUND = -70,

    /** Attempt to operate on a stream in a way that is not support
     * since data has already been written-to/read-from the stream. */
    SKSTREAM_ERR_PREV_DATA = -71,

    /** The stream is already open. */
    SKSTREAM_ERR_PREV_OPEN = -72,

    /** The file's content type does not support the action: attempt to
     * skStreamRead() on a SK_CONTENT_TEXT stream, attempt to
     * skStreamPrint() to a binary or SiLK stream, etc. */
    SKSTREAM_ERR_UNSUPPORT_CONTENT = -73,

    /** The skStreamSetCopyInput() function has already been called on
     * this stream. */
    SKSTREAM_ERR_PREV_COPYINPUT = -74,


    /* Errors due to missing or outdated libraries */

    /** The stream is compressed with a compression method that SiLK
     * does not recognize. */
    SKSTREAM_ERR_COMPRESS_INVALID = -80,

    /** The stream is compressed with a unavailable compression mode;
     * for example, you're operating on a gzipped file but SiLK was
     * not linked with gzip. */
    SKSTREAM_ERR_COMPRESS_UNAVAILABLE = -81,


    /* User errors when creating a new stream */

    /** The file's header does not contain the SiLK magic number---for
     * files that contain SK_CONTENT_SILK. */
    SKSTREAM_ERR_BAD_MAGIC = -16,

    /** Attempt to open a stream for writing that is bound to a file
     * name that already exists. */
    SKSTREAM_ERR_FILE_EXISTS = -17,

    /** Attempt to read or write binary data on a terminal (tty) */
    SKSTREAM_ERR_ISTERMINAL = -18,

    /** Attempt to invoke the paging program failed. */
    SKSTREAM_ERR_NOPAGER = -19,

    /** Could not get a read lock on the stream. */
    SKSTREAM_ERR_RLOCK = -20,

    /** The call to fdopen() failed. */
    SKSTREAM_ERR_SYS_FDOPEN = -21,

    /** The call to lseek() failed. */
    SKSTREAM_ERR_SYS_LSEEK = -22,

    /** The call to open() failed. */
    SKSTREAM_ERR_SYS_OPEN = -23,

    /** The call to mkstemp() failed. */
    SKSTREAM_ERR_SYS_MKSTEMP = -24,

    /** The file's read/write status does not support the action: an
     * attempt to write to "stdin", an attempt to append to a FIFO or
     * a gzipped file. */
    SKSTREAM_ERR_UNSUPPORT_IOMODE = -25,

    /** Could not get a read lock on the stream. */
    SKSTREAM_ERR_WLOCK = -26,

    /** The call to fork() failed. */
    SKSTREAM_ERR_SYS_FORK = -27,

    /** The call to pipe() failed. */
    SKSTREAM_ERR_SYS_PIPE = -28,

    /** The call to mkdir() failed. */
    SKSTREAM_ERR_SYS_MKDIR = -29,

    /** The call to fcntl(fd, F_GETFL) failed. */
    SKSTREAM_ERR_SYS_FCNTL_GETFL = -30,

    /* Errors that may occur while processing the stream that
     * typically indicate a fatal condition. */

    /** Value returned skStreamRead() and skStreamWrite() when an error
     * has occured. */
    SKSTREAM_ERR_IO = -1,

    /** Error with internal buffering. */
    SKSTREAM_ERR_IOBUF = -2,

    /** There was an error writing to the stream. */
    SKSTREAM_ERR_WRITE = -3,

    /** There was an error reading from the stream. */
    SKSTREAM_ERR_READ = -4,

    /** Value returned when the input is exhausted.  Note that reaching
     * the end of a file is not really an "error". */
    SKSTREAM_ERR_EOF = -5,

    /** Error occurred in a gz* function */
    SKSTREAM_ERR_ZLIB = -6,

    /** The read returned fewer bytes than required for a complete
     * record. */
    SKSTREAM_ERR_READ_SHORT = -7,

    /** The operation requires the stream to be bound to a seekable
     * file, and the stream is not. */
    SKSTREAM_ERR_NOT_SEEKABLE = -8,

    /** The call to ftruncate() failed. */
    SKSTREAM_ERR_SYS_FTRUNCATE = -9,


    /* The following set of errors are general errors that occur when
     * opening a SiLK file for read, write, or append. */

    /** The file has a format that does not support this operation.
     * See also the next error code. */
    SKSTREAM_ERR_UNSUPPORT_FORMAT = 32,

    /** An operation that requires SiLK Flow data is attempting to open
     * a SiLK file that does not contain flows. */
    SKSTREAM_ERR_REQUIRE_SILK_FLOW = 33,

    /** The file or record has a version that this version of libsilk
     * does not know how to handle */
    SKSTREAM_ERR_UNSUPPORT_VERSION = 34,


    /* The following set of errors affect only the current record;
     * they occur when trying to write a record to a stream.  These
     * are considered non-fatal.  Use the SKSTREAM_ERROR_IS_FATAL()
     * macro below. */

    /** The record's start time is less than the file's start time */
    SKSTREAM_ERR_STIME_UNDRFLO = 64,

    /** The record's start time at least an hour greater than the
     * file's start time */
    SKSTREAM_ERR_STIME_OVRFLO = 65,

    /** The record's elapsed time is greater than space allocated for
     * duration in this file format */
    SKSTREAM_ERR_ELPSD_OVRFLO = 66,

    /** The record contains more than the number of packets allowed in
     * this file format */
    SKSTREAM_ERR_PKTS_OVRFLO = 67,

    /** The record contains a 0 value in the packets field. */
    SKSTREAM_ERR_PKTS_ZERO = 68,

    /** The byte-per-packet value is too large to fit into the space
     * provided by this file format. */
    SKSTREAM_ERR_BPP_OVRFLO = 69,

    /** The records contains an SNMP value too large to fit into the
     * space allocated in this file format. */
    SKSTREAM_ERR_SNMP_OVRFLO = 70,

    /** The records contains a SensorID too large to fit into the space
     * allocated in this file format. */
    SKSTREAM_ERR_SENSORID_OVRFLO = 71,

    /** The record's IP protocol is not supported by the file's format;
     * for example, trying to store a non-TCP record in a FT_RWWWW
     * file. */
    SKSTREAM_ERR_PROTO_MISMATCH = 72,

    /** The record's "packets" value is greater than the "bytes" value. */
    SKSTREAM_ERR_PKTS_GT_BYTES = 73,

    /** The record is an IPv6 record which is not supported. */
    SKSTREAM_ERR_UNSUPPORT_IPV6 = 74,

    /** The record contains more than the number of bytes (octets)
     * allowed in this file format */
    SKSTREAM_ERR_BYTES_OVRFLO = 75,

    /* Errors that may occur which indicate an error with one
     * line/record, but which are normally not fatal */

    /** Returned by skStreamGetLine() when an input line is longer than
     * the specified buffer size. */
    SKSTREAM_ERR_LONG_LINE = 96

} skstream_err_t;


/**
 *  SKSTREAM_ERROR_IS_FATAL(err);
 *
 *    Evaluates to a true value if error is a fatal error, false otherwise.
 */
#define SKSTREAM_ERROR_IS_FATAL(err) ((err) != SKSTREAM_OK && (err) < 64)


/**
 *    Set 'stream' to operate on the file specified in 'pathname';
 *    'pathname' may also be one of "stdin", "stdout", or "stderr".
 *    Return SKSTREAM_OK on success, or one of these error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_PREV_BOUND
 *    SKSTREAM_ERR_INVALID_INPUT
 *    SKSTREAM_ERR_ISTERMINAL
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 */
int
skStreamBind(
    skstream_t         *stream,
    const char         *pathname);




/**
 *    Check that the compression method used by 'stream' is known and
 *    is available.  Return SKSTREAM_OK if it is; otherwise return an
 *    error code as described below and print an error message using
 *    the 'err_fn' when it is provided.
 *
 *    If the stream uses an unknown compression method, return
 *    SKSTREAM_ERR_COMPRESS_INVALID.  If the compression method is
 *    recognized but not available in this compilation of SiLK, return
 *    SKSTREAM_ERR_COMPRESS_UNAVAILABLE.
 */
int
skStreamCheckCompmethod(
    skstream_t         *stream,
    sk_msg_fn_t         err_fn);


/**
 *    Check several attributes of the SiLK header on the file
 *    associated with 'stream'.  If the header passes all tests,
 *    return SKSTREAM_OK.  If the header fails a test an error code is
 *    returned; in addtion, if 'err_fn' is provided, that function
 *    will be called to print an error message.
 *
 *    If the stream's format is not 'file_format', return
 *    SKSTREAM_ERR_UNSUPPORT_FORMAT.
 *
 *    If the version of the records in the stream is below
 *    'min_rec_version' or above 'max_rec_version', return
 *    SKSTREAM_ERR_UNSUPPORT_VERSION.
 *
 *    The skStreamCheckCompmethod() function is also called.
 */
int
skStreamCheckSilkHeader(
    skstream_t         *stream,
    sk_file_format_t    file_format,
    sk_file_version_t   min_rec_version,
    sk_file_version_t   max_rec_version,
    sk_msg_fn_t         err_fn);


/**
 *    Flush any data on the 'stream' and closes the underlying file
 *    descriptor.  Return SKSTREAM_OK on success, or one of these
 *    error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_WRITE
 *    SKSTREAM_ERR_IOBUF
 *    SKSTREAM_ERR_ZLIB
 */
int
skStreamClose(
    skstream_t         *stream);


/**
 *    Create a new stream at the location pointed to by 'new_stream';
 *    the action to perform on 'new_stream' is determined by
 *    'read_write_append', and 'content_type' specified the content of
 *    'new_stream'.  Return SKSTREAM_OK on success, or one of these
 *    error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_ALLOC
 */
int
skStreamCreate(
    skstream_t        **new_stream,
    skstream_mode_t     read_write_append,
    skcontent_t         content_type);


/**
 *    Closes the stream at '*stream', if open, destroys the stream
 *    pointed at by 'stream' and sets '*stream' to NULL.  If 'stream'
 *    is NULL or its value is NULL, no action is taken and the
 *    function returns.  Return SKSTREAM_OK on success, or any of the
 *    error codes listed by skStreamClose().
 */
int
skStreamDestroy(
    skstream_t        **stream);


/**
 *    Associate 'stream' with the previously opened file descriptor
 *    'file_desc'.  The 'stream' must have been previously bound to a
 *    filename.  Return SKSTREAM_OK on success, or one of these error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_BOUND
 *    SKSTREAM_ERR_PREV_OPEN
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_INVALID_INPUT
 *    SKSTREAM_ERR_UNSUPPORT_COMPRESS
 *    SKSTREAM_ERR_ALLOC
 */
int
skStreamFDOpen(
    skstream_t         *stream,
    int                 file_desc);


/**
 *    Flush any data in the stream's buffers to disk; has no effect on
 *    a stream open for reading.  Return SKSTREAM_OK on success, or
 *    one of these error codes:
 *
 *    SKSTREAM_ERR_IOBUF
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_WRITE
 */
int
skStreamFlush(
    skstream_t         *stream);


/**
 *    Return the type of content associated with the stream.
 */
skcontent_t
skStreamGetContentType(
    const skstream_t   *stream);


/**
 *    Return the file descriptor associated with 'stream'.
 */
int
skStreamGetDescriptor(
    const skstream_t   *stream);


/**
 *    Return the value of errno that is cached on 'stream'.
 *
 *    The skstream_t normally only caches errno for failed commands,
 *    so the returned value may not reflect the errno from the most
 *    recent command.  See also skStreamGetLastReturnValue().
 */
int
skStreamGetLastErrno(
    const skstream_t   *stream);


/**
 *    Return the result (the error code) that was returned by the most
 *    recent function that modified 'stream'.
 *
 *    Most functions that modify the stream store the return value on
 *    the stream as well as returning it to the caller.  This function
 *    returns the stored value.
 *
 *    Unlike skStreamGetLastErrno(), nearly all functions store the
 *    return value before returning it---whether the function was
 *    successful or reported an error.
 */
ssize_t
skStreamGetLastReturnValue(
    const skstream_t   *stream);


/**
 *    Fill 'value' with the limit implied by the error code given in
 *    'limit_id', which should be an skstream_err_t.
 *
 *    The 'stream' must be a SiLK stream that has a header.  If it is
 *    not, SKSTREAM_ERR_REQUIRE_SILK_FLOW is returned.
 *
 *    The following 'limit_id' values are supported:
 *
 *    SKSTREAM_ERR_STIME_UNDRFLO -- Fills 'value' with the minimum
 *    starting time supported, as milliseconds since the UNIX epoch.
 *    This is either 0 or the start hour specified in the stream's
 *    header.
 *
 *    SKSTREAM_ERR_STIME_OVRFLO -- Fills 'value' with the maximum
 *    starting time supported, as milliseconds since the UNIX epoch.
 *    This will be one hour beyond the starting time in the stream's
 *    header, or a later time depending on the file format.
 *
 *    SKSTREAM_ERR_ELPSD_OVRFLO -- Fills 'value' with the maximum flow
 *    duration supported, in milliseconds.  This value will be between
 *    2,047,000 and 4,294,967,295, depending on file format.
 *
 *    SKSTREAM_ERR_PKTS_ZERO -- Fills 'value' with 1, which is the
 *    minimum packet value supported by most formats.
 *
 *    SKSTREAM_ERR_PKTS_OVRFLO -- Fills 'value' with the maximum
 *    packet count supported.  This value will be between 16,777,215
 *    and 4,294,967,295, depending on file format.
 *
 *    SKSTREAM_ERR_BPP_OVRFLO -- Fills 'value' with the maximum
 *    byte-per-packet ratio supported.  This value will be between
 *    16,383 and 4,294,967,295, depending on file format.
 *
 *    SKSTREAM_ERR_SNMP_OVRFLO -- Fills 'value' with the maximum SNMP
 *    value supported.  This is 255 for some formats, 65,535 for other
 *    formats, or 0 if the format ignores SNMP interfaces.
 *
 *    SKSTREAM_ERR_SENSORID_OVRFLO -- Fills 'value' with the maximum
 *    sensor ID value supported.  This is 65,535 for most formats, but
 *    may be as small as 63 for very old formats.
 *
 *    Any other value for 'limit_id' leaves 'value' untouched and
 *    returns SKSTREAM_ERR_INVALID_INPUT.
 */
int
skStreamGetLimit(
    const skstream_t   *stream,
    int                 limit_id,
    int64_t            *value);


/**
 *    Read a line of text from 'stream' and store it in 'out_buffer',
 *    a character array of buf_size characters.  If 'line_count' is
 *    non-NULL, it's value will be INCREMENTED by the number of lines
 *    read, typically 1.  The line will be truncated at the newline
 *    character---the newline will not be returned.  Return
 *    SKSTREAM_OK on success, or SKSTREAM_ERR_EOF at the end of file.
 *
 *    Lines containing only whitespace are ignored.  If the stream's
 *    comment character has been set, comments are stripped from the
 *    input as well, and lines containing only comments are ignored.
 *
 *    If a line is longer than 'buf_size', the line is ignored and
 *    SKSTREAM_ERR_LONG_LINE is returned.  The value in 'out_buffer'
 *    will be random.
 *
 *    This function requires that 'stream' be an SK_IO_READ stream
 *    that has a content type of SK_CONTENT_TEXT.
 *
 *    In addition to the above return values, the function may also
 *    return:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_SYS_FDOPEN
 */
int
skStreamGetLine(
    skstream_t         *stream,
    char               *out_buffer,
    size_t              buf_size,
    int                *line_count);


/**
 *    Return a value indicating whether the stream is being used for
 *    reading, writing, or appending.
 */
skstream_mode_t
skStreamGetMode(
    const skstream_t   *stream);


/**
 *    For an open stream, returns the name of the paging program if it
 *    is being used, or NULL if a pager is not in use.  For a stream
 *    that is not yet open, returns the name of the paging program
 *    which MAY be used, or NULL if paging has not been requested.
 */
const char *
skStreamGetPager(
    const skstream_t   *stream);


/**
 *    Return the pathname to which 'stream' has been bound, or NULL if
 *    the stream is unbound.
 */
const char *
skStreamGetPathname(
    const skstream_t   *stream);


/**
 *    Return the number of SiLK Flow records that have been processed
 *    by 'stream' since is was opened.  This will be the number of
 *    records in the file, unless the file was opened for append, in
 *    which case it is the number of records appeneded.
 *
 *    A return value of ((uint64_t)(-1)) indicates that 'stream' does
 *    not contain SiLK Flow records.
 */
uint64_t
skStreamGetRecordCount(
    const skstream_t   *stream);


/**
 *    Return the SiLK file header for the stream.  Returns NULL if the
 *    stream is not a SiLK stream.
 */
sk_file_header_t *
skStreamGetSilkHeader(
    const skstream_t   *stream);


/**
 *    Return 1 if 'stream' supports IPv6 addresses, 0 otherwise.
 */
int
skStreamGetSupportsIPv6(
    const skstream_t   *stream);


/**
 *    Return the maximum possible file size that would be created if
 *    the file were to be flushed.
 */
off_t
skStreamGetUpperBound(
    skstream_t         *stream);


/**
 *    Initialize global state used by the stream library.  For
 *    example, check environment variables used by the stream library.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppRegister().
 */
int
skStreamInitialize(
    void);


/**
 *    Return a non-zero value if 'stream' is a seekable stream; return
 *    0 otherwise.
 */
int
skStreamIsSeekable(
    const skstream_t   *stream);


/**
 *    Return a non-zero value if 'stream' is bound to the standard
 *    output.
 */
int
skStreamIsStdout(
    const skstream_t   *stream);


/**
 *    Fill 'buffer' with the error message that corresponds to the
 *    stream error code 'errcode'.  The caller must provide the length
 *    of 'buffer' in 'buffer_len'.  The 'stream' object may be NULL;
 *    if non-NULL, it can provide additional context for the error
 *    message.  Return the value returned by the printf()-like
 *    function used to format the message.
 *
 *    See also skStreamGetLastReturnValue(), skStreamPrintLastErr().
 */
int
skStreamLastErrMessage(
    const skstream_t   *stream,
    ssize_t             errcode,
    char               *buffer,
    size_t              buffer_len);


/**
 *    Block until the stream has a lock on the file associated with
 *    'stream'.  Return SKSTREAM_OK on success or if the stream is
 *    not-seekable, or one of the following error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_RLOCK
 *    SKSTREAM_ERR_WLOCK
 */
int
skStreamLockFile(
    skstream_t         *stream);


/**
 *    Create any directories that would be required before opening the
 *    file bound to 'stream'.
 */
int
skStreamMakeDirectory(
    skstream_t         *stream);


/**
 *    Like skStreamOpen(), open the file associated with 'stream'.
 *    However, this function passes the pathname associated with
 *    'stream' to the mkstemp() library call to create a temporary
 *    file, so the pathname associated with the file should be
 *    suitable for mkstemp()---that is, it should end in 6 or more 'X'
 *    characters.  Return SKSTREAM_OK on success, or one of the
 *    following error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_BOUND
 *    SKSTREAM_ERR_PREV_OPEN
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_SYS_MKSTEMP
 */
int
skStreamMakeTemp(
    skstream_t         *stream);


/**
 *    Open the file associated with 'stream'.  Note that
 *    skStreamOpen() must be called even when the stream has been
 *    bound to a standard stream, i.e., "stdin", "stdout", or
 *    "stderr".  For an output stream, the target file must not
 *    previously exist, unless it is a FIFO or a character special
 *    file, i.e., "/dev/null".
 *
 *    Return SKSTREAM_OK on success, or one of the following error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_BOUND
 *    SKSTREAM_ERR_PREV_OPEN
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_SYS_OPEN
 *    SKSTREAM_ERR_FILE_EXISTS
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_UNSUPPORT_COMPRESS
 */
int
skStreamOpen(
    skstream_t         *stream);


/**
 *    A convenience function for creating a stream that processes SiLK
 *    flow records.  This function will create a stream at the
 *    location specified by 'stream', set its mode to
 *    'read_write_append', bind it to 'pathname', and open it.  If the
 *    'read_write_append' mode is SK_IO_READ or SK_IO_APPEND, this
 *    function will also read the file's header.
 *
 *    Returns SKSTREAM_OK on success.
 *
 *    If there is an error opening the stream, 'stream' will be left
 *    in a partially allocated/opened state.  The caller should invoke
 *    skStreamDestroy() to destroy the stream.
 */
int
skStreamOpenSilkFlow(
    skstream_t        **stream,
    const char         *pathname,
    skstream_mode_t     read_write_append);


/**
 *    Allow 'stream' to display its output a screenful at a time by
 *    invoking the program named by 'pager' and pass the output of
 *    'stream' through it.  This function requires that 'stream' be an
 *    SK_IO_WRITE stream that has a content type of SK_CONTENT_TEXT.
 *
 *    'stream' may be open or not-yet-open; if open, no data can have
 *    been written to 'stream' yet.  If 'stream' is already open, this
 *    function will invoke the pager; otherwise, the pager will be
 *    invoked on the first attempt to skStreamPrint() to 'stream'.
 *
 *    Return SKSTREAM_OK on success, or one of the following error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_ATTRIBUTE_FIXED
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_SYS_FDOPEN
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 */
int
skStreamPageOutput(
    skstream_t         *stream,
    const char         *pager);


/**
 *    Perform printf()-style formatting and write the result to
 *    'stream'.  On the first call to this funtion for 'stream', the
 *    pager for 'stream' will be invoked if the paging program was set
 *    and output would be to a terminal.  This function requires that
 *    'stream' be an SK_IO_WRITE stream that has a content type of
 *    SK_CONTENT_TEXT.
 *
 *    Return SKSTREAM_OK on success, or one of the following error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_WRITE
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 */
#ifdef TEST_PRINTF_FORMATS
#define skStreamPrint(stream, ...) printf(__VA_ARGS__)
#else
int
skStreamPrint(
    skstream_t         *stream,
    const char         *format,
    ...)
    SK_CHECK_PRINTF(2, 3);
#endif


/**
 *    Print, using the function pointed to by err_fn, a description of
 *    the last error that occured on 'stream', where 'err_code' is the
 *    return code that a function returned.  'stream' may be NULL.
 *
 *    See also skStreamGetLastReturnValue(), skStreamLastErrMessage().
 */
void
skStreamPrintLastErr(
    const skstream_t   *stream,
    ssize_t             err_code,
    sk_msg_fn_t         err_fn);


/**
 *    Attempt to read 'count' bytes from 'stream', putting the data
 *    into 'buf'.  Return the number of bytes actually read, 0 for end
 *    of file, and -1 on error.
 *
 *    When 'buf' is NULL, 'count' bytes are "read" but the data is
 *    dropped.  The function returns the number of bytes "read", or -1
 *    for error.
 *
 *    The function will use a buffered reader, gzread(), or raw read()
 *    as appropriate.  For a raw read(), the function continues to call
 *    read() until it has read 'count' bytes or read() returns 0 or
 *    -1.
 *
 *    When the function returns -1, there is no way to determine how
 *    many bytes were read prior to the error.
 */
ssize_t
skStreamRead(
    skstream_t         *stream,
    void               *buf,
    size_t              count);


/**
 *    Read a single SiLK Flow record from 'stream'.
 */
int
skStreamReadRecord(
    skstream_t         *stream,
    rwRec              *rec);


/**
 *    Attempt to read the SiLK file header from 'stream', putting the
 *    data into 'hdr'.  This function requires that 'stream' contain
 *    SK_CONTENT_SILK or SK_CONTENT_SILK_FLOW and that it's mode be
 *    either SK_IO_READ or SK_IO_APPEND.
 *
 *    An attempt to read the header multiple times will result in
 *    SKSTREAM_ERR_PREV_DATA.
 *
 *    When 'stream' is open for SK_IO_APPEND, this function will seek
 *    to the end of the file after reading the header.
 *
 *    Return SKSTREAM_OK on success, or one of the following error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_READ
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_PREV_DATA
 *    SKSTREAM_ERR_BAD_MAGIC
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 */
int
skStreamReadSilkHeader(
    skstream_t         *stream,
    sk_file_header_t  **hdr);


/**
 *    Attempt to read the first 8 bytes of 'stream'.  (Eight bytes is
 *    the minimum header size used by all versions of SiLK.)
 */
int
skStreamReadSilkHeaderStart(
    skstream_t         *stream);


/**
 *    Attempt to read all (remaining) data in 'stream', and return
 *    that content.  Set 'length' to the number of bytes of data from
 *    from the stream.
 *
 *    The caller is responsible for calling free() on the value
 *    returned from this function.
 *
 *    An extra NUL byte is added to the data read from the stream, but
 *    that byte is not included in 'length'.  (This guarantees that
 *    textual files are NUL terminated.)
 *
 *    On error, NULL is returned. length is indeterminate, and any
 *    data read from the stream is lost.  You may call
 *    skStreamPrintLastErr() with an 'err_code' of -1 to find the
 *    exact error.
 */
void *
skStreamReadToEndOfFile(
    skstream_t         *stream,
    ssize_t            *length);


/**
 *    Set the comment string for a textual input file to
 *    'comment_start'.  This function requires that 'stream' be an
 *    SK_IO_READ stream that contains SK_CONTENT_TEXT.  Return
 *    SKSTREAM_OK on success, or one of the following error codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 */
int
skStreamSetCommentStart(
    skstream_t         *stream,
    const char         *comment_start);


/**
 *    Set the compression method on 'stream' to 'comp_method'.
 */
#define skStreamSetCompressionMethod(stream, comp_method)               \
    (skHeaderSetCompressionMethod(skStreamGetSilkHeader(stream),        \
                                  (comp_method)))


/**
 *    Inform 'read_stream' that all records it reads must be written
 *    to 'write_stream'.  'read_stream' and 'write_stream' must both
 *    contain SiLK Flow records.  This function must be called before
 *    data is read from the 'read_stream'.
 */
int
skStreamSetCopyInput(
    skstream_t         *read_stream,
    skstream_t         *write_stream);


/**
 *    Specify how 'stream' handles IPv6 records, or IPv4 records in a
 *    mixed IPv4/IPv6 environment.  The 'stream' must represent a SiLK
 *    stream.
 */
int
skStreamSetIPv6Policy(
    skstream_t         *stream,
    sk_ipv6policy_t     policy);


/**
 *    Do not use buffering on this stream.  This must be called prior
 *    to opening the stream.
 */
int
skStreamSetUnbuffered(
    skstream_t         *stream);


/**
 *    Attempt to move forward in 'stream' by 'skip_count' records.  If
 *    'records_skipped' is not NULL, the number of records skipped
 *    will be recorded in that location.
 */
int
skStreamSkipRecords(
    skstream_t         *stream,
    size_t              skip_count,
    size_t             *records_skipped);


/**
 *    Destroy any global state held by the stream library.
 *
 *    Application writers do not need to call this function as it is
 *    called by skAppUnregister().
 */
void
skStreamTeardown(
    void);


/**
 *    Return the current byte offset into the underlying stream.
 *    Return -1 if the stream is unopend, is unseekable, or if another
 *    error occurs.
 */
off_t
skStreamTell(
    skstream_t         *stream);


/**
 *    Set the length of the file bound to 'stream' to 'length'.
 *
 *    This function will call skStreamFlush() on the stream prior to
 *    setting its length.
 *
 *    The value of 'length' should be a value determined before any
 *    new data has been written to the file, or after a call to
 *    skStreamFlush() to ensure there is no unsaved data.
 *
 *    Return SKSTREAM_OK on success.  If 'stream' is not open for
 *    writing or appending, return SKSTREAM_ERR_UNSUPPORT_IOMODE.  If
 *    stream's content is SK_CONTENT_TEXT, return
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT.  If 'stream' is not seekable,
 *    return SKSTREAM_ERR_NOT_SEEKABLE.  Return
 *    SKSTREAM_ERR_SYS_FTRUNCATE if the call to ftruncate() fails.
 *
 *    If the call to skStreamFlush() returns an error value, the
 *    ftruncate() call is still attempted, and the function will
 *    return SKSTREAM_ERR_SYS_FTRUNCATE if the ftruncate() call
 *    failed, or the error status from the skStreamFlush() call.  If
 *    skStreamFlush() fails, there may be unflushed buffers that the
 *    system will attempt to flush when the stream is destroyed,
 *    making the file's length different than 'length'.
 *
 *    In addition, the function may return:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_CLOSED
 */
int
skStreamTruncate(
    skstream_t         *stream,
    off_t               length);


/**
 *    Closes the stream at 'stream', if open, and unbinds the stream
 *    from the filename.  If 'stream' is NULL, no action is taken and
 *    the function returns.  Return SKSTREAM_OK on success, or any of
 *    the error codes listed by skStreamClose().
 *
 *    Currently, a stream cannot be re-bound, so this function is of
 *    limited utility.
 */
int
skStreamUnbind(
    skstream_t         *stream);


/**
 *    Attempt to write 'count' bytes from 'buf' to 'stream'.  Return
 *    the number of bytes actually written or -1 on error.
 *
 *    The function will use a buffered writer, gzwrite(), or raw
 *    write() as appropriate.  For a raw write(), the function
 *    continue to call write() until it has written 'count' bytes or
 *    write() returns -1.
 */
ssize_t
skStreamWrite(
    skstream_t         *stream,
    const void         *buf,
    size_t              count);


/**
 *    Write the SiLK Flow record 'rec' to 'stream'.
 */
int
skStreamWriteRecord(
    skstream_t         *stream,
    const rwRec        *rec);


/**
 *    Attempt to write 'hdr_size' bytes from 'buf' to 'stream', with
 *    the following caveat: the first eight bytes of 'hdr' will be
 *    modified to contain the SiLK magic file number, and the values
 *    that were specified in the calls to skStreamSetByteOrder(),
 *    skStreamSetSilkFormat(), skStreamSetSilkVersion(), and
 *    skStreamSetCompressionMethod().
 *
 *    If 'hdr' is shorter than eight bytes, return
 *    SKSTREAM_ERR_INVALID_INPUT.  If fewer than 'hdr_size' bytes were
 *    written, return SKSTREAM_ERR_WRITE.  This function requires that
 *    'stream' be an SK_IO_WRITE stream containing SK_CONTENT_SILK or
 *    SK_CONTENT_SILK_FLOW.
 *
 *    An attempt to write the header multiple times will result in
 *    SKSTREAM_ERR_PREV_DATA.
 *
 *    Return SKSTREAM_OK on success, or one of the following error
 *    codes:
 *
 *    SKSTREAM_ERR_NULL_ARGUMENT
 *    SKSTREAM_ERR_CLOSED
 *    SKSTREAM_ERR_NOT_OPEN
 *    SKSTREAM_ERR_INVALID_INPUT
 *    SKSTREAM_ERR_WRITE
 *    SKSTREAM_ERR_ALLOC
 *    SKSTREAM_ERR_PREV_DATA
 *    SKSTREAM_ERR_UNSUPPORT_IOMODE
 *    SKSTREAM_ERR_UNSUPPORT_CONTENT
 */
int
skStreamWriteSilkHeader(
    skstream_t         *stream);


#ifdef __cplusplus
}
#endif
#endif /* _SKSTREAM_H */

/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
