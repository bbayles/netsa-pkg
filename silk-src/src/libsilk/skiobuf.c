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
**  Routines for buffered file io.
*/

#include <silk/silk.h>

RCSIDENT("$SiLK: skiobuf.c b2b562f1ea39 2023-02-20 17:50:25Z mthomas $");

#include <silk/utils.h>
#include "skiobuf.h"
#include "skstream_priv.h"  /* for declaration of skIOBufBindGzip() */

SK_DIAGNOSTIC_IGNORE_PUSH("-Wundef")

#if SK_ENABLE_SNAPPY
#include <snappy-c.h>
#endif
#if SK_ENABLE_LZO
#include SK_LZO_HEADER_NAME
#endif
#ifdef SK_HAVE_LZO1X_DECOMPRESS_ASM_FAST_SAFE
#include SK_LZO_ASM_HEADER_NAME
#endif

SK_DIAGNOSTIC_IGNORE_POP("-Wundef")


/*
 *  skiobuf Input/Output Format
 *
 *    For compressed streams, blocks are written to the storage
 *    medium.  Each block is written to the storage medium as an
 *    8-byte header, followed by the compressed block.  The format is
 *    as follows:
 *
 *    byte 0-3: 4-byte compressed size (network byte order)
 *    byte 4-7: 4-byte uncompressed size (network byte order)
 *    byte 8- : The compressed data (compressed size number of bytes)
 *
 *    The compressed size in bytes 0-3 is the size of the data portion
 *    only; it does not include the 8 byte header.
 *
 *    When reading, a compressed size of 0 is considered identical to
 *    an end-of-file.  This allows one to embed an skiobuf compressed
 *    stream within another stream of data.
 *
 *    For uncompressed streams, skiobuf merely acts as a buffered
 *    reader/writer.  Although bytes are read and written from or to
 *    the storage medium as blocks, no headers are read or written.
 */

/*
 *    The iobuf_opts_t union contains options/parameters specific to a
 *    particular compression method.
 *
 */
typedef union iobuf_opts_un {
#if SK_ENABLE_ZLIB
    /* zlib */
    struct {
        int level;
    } zlib;
#endif  /* SK_ENABLE_ZLIB */

#if SK_ENABLE_LZO
    /* lzo */
    struct {
        uint8_t *scratch;
    } lzo;
#endif  /* SK_ENABLE_LZO */

    char nothing;        /* Just to keep the union from being empty */
} iobuf_opts_t;


/*
 *    Each compressed block begins with a big-endian encoding of the
 *    compr_sizes_t structure which gives the size of the commpressed
 *    block---this is, the number of bytes on disk (not including this
 *    structure)---and the number of bytes that compressed block
 *    should expand to in RAM.
 */
typedef struct compr_sizes_st {
    uint32_t compr_size;
    uint32_t uncompr_size;
} compr_sizes_t;


/*
 *    sk_iobuf_t represents an IO buffer.
 */
struct sk_iobuf_st {
    /* Compression method */
    sk_compmethod_t compr_method;
    /* Compression options */
    iobuf_opts_t    compr_opts;

    /* Compression buffer */
    uint8_t        *compr_buf;
    /* Decompression buffer */
    uint8_t        *uncompr_buf;

    /* Size of compr buffer */
    uint32_t        compr_buf_size;
    /* Size of uncompr buffer, typically same as 'block_size' */
    uint32_t        uncompr_buf_size;

    /* The uncompressed block size set by skIOBufSetBlockSize(), or
     * SKIOBUF_DEFAULT_BLOCKSIZE */
    uint32_t        block_size;
    /* The quanta (record) size for the uncompressed block set by
     * skIOBufSetRecordSize(); ensures records do not span multiple
     * blocks.  Default is 1 (SKIOBUF_DEFAULT_RECORDSIZE). */
    uint32_t        block_quantum;

    /* Location of start of the current compressed block on disk */
    off_t           block_pos;
    /* Size of current compressed block on disk */
    uint32_t        disk_block_size;
    /* Byte position in buffer */
    uint32_t        pos;
    /* Maximim bytes allowed in uncompressed buffer, based on the
     * block_size */
    uint32_t        max_bytes;

    /* File descriptor */
    void           *fd;
    /* Function pointers that operate on the file descriptor */
    skio_abstract_t io;

    /* Total bytes read from or written to disk */
    off_t           total;

    /* The errno of most recent error */
    int             io_errno;
    /* Source code line of the error */
    uint32_t        error_line;

    /* When reading, set for each compressed block once the compressed
     * block is in memory */
    unsigned        in_core   : 1;
    /* When reading, set for each compressed block once the block has
     * been uncompressed */
    unsigned        is_uncompr: 1;
    /* Set once the file descriptor is valid; that is, after a call to
     * skIOBufBindAbstract() */
    unsigned        fd_valid  : 1;
    /* Set if skio_abstract_t does not provide a seek method */
    unsigned        no_seek   : 1;
    /* Set once a read or write has occurred to prevent the user from
     * changing the block size or record size */
    unsigned        used      : 1;
    /* Set at creation if this IO Buffer is used for writing */
    unsigned        is_writer : 1;
    /* End of file or flushed */
    unsigned        at_eof    : 1;
    /* Error state? */
    unsigned        has_error : 1;
    /* Internal or external error? */
    unsigned        has_interr: 1;
    /* IO error */
    unsigned        has_ioerr : 1;
};
/* typedef struct sk_iobuf_st sk_iobuf_t; */


/*
 *    The skio_uncomp_t values tell skio_uncompr() how to handle a
 *    compressed block.
 */
typedef enum {
    SKIO_UNCOMP_NORMAL,         /* Normal read of the block */
    SKIO_UNCOMP_SKIP,           /* Only read sizes of the block */
    SKIO_UNCOMP_REREAD          /* Actually read the skipped block */
} skio_uncomp_t;


/*    Error codes, messages, macros  */

enum internal_errors {
    ESKIO_BADOPT = 0,
    ESKIO_BADCOMPMETHOD,
    ESKIO_BLOCKSIZE,
    ESKIO_COMP,
    ESKIO_INITFAIL,
    ESKIO_MALLOC,
    ESKIO_NOFD,
    ESKIO_NOREAD,
    ESKIO_NOWRITE,
    ESKIO_SHORTREAD,
    ESKIO_SHORTWRITE,
    ESKIO_TOOBIG,
    ESKIO_UNCOMP,
    ESKIO_USED
};

static const char* internal_messages[] = {
    "Illegal compression or decompression option",    /* ESKIO_BADOPT */
    "Bad compression method",                         /* ESKIO_BADCOMPMETHOD */
    "Block size is too large",                        /* ESKIO_BLOCKSIZE */
    "Error during compression",                       /* ESKIO_COMP */
    "Compression initialization failed",              /* ESKIO_INITFAIL */
    "Out of memory",                                  /* ESKIO_MALLOC */
    "File descriptor is not set",                     /* ESKIO_NOFD */
    "Attempt to read from an IO buffer writer",       /* ESKIO_NOREAD */
    "Attempt to write to an IO buffer reader",        /* ESKIO_NOWRITE */
    "Could not read complete compressed block",       /* ESKIO_SHORTREAD */
    "Could not write complete compressed block",      /* ESKIO_SHORTWRITE */
    "Count is too large",                             /* ESKIO_TOOBIG */
    "Error during decompression",                     /* ESKIO_UNCOMP */
    "Parameter set on IO buffer after buffer has been used" /* ESKIO_USED */
};

#define SKIOBUF_INTERNAL_ERROR(fd, err)         \
    {                                           \
        if (!(fd)->has_error) {                 \
            (fd)->io_errno = (int)(err);        \
            (fd)->has_error = 1;                \
            (fd)->has_interr = 1;               \
            (fd)->error_line = __LINE__;        \
        }                                       \
        return -1;                              \
    }

#define SKIOBUF_EXTERNAL_ERROR(fd)              \
    {                                           \
        if (!(fd)->has_error) {                 \
            (fd)->io_errno = errno;             \
            (fd)->has_error = 1;                \
            (fd)->error_line = __LINE__;        \
        }                                       \
        return -1;                              \
    }

#define SKIOBUF_IO_ERROR(fd)                    \
    {                                           \
        if (!(fd)->has_error) {                 \
            (fd)->io_errno = errno;             \
            (fd)->has_error = 1;                \
            (fd)->has_ioerr = 1;                \
            (fd)->fd_valid = 0;                 \
            (fd)->error_line = __LINE__;        \
        }                                       \
        return -1;                              \
    }


/*    Signatures of compression method functions  */

/* Initialization.  Should set the default opts. */
typedef int
(*init_method_fn_t)(
    iobuf_opts_t       *opts);

/* Deinitialization.  Should free any default opts. */
typedef int
(*uninit_method_fn_t)(
    iobuf_opts_t       *opts);

/* Size computation.  Should return the maximum compressed size given
 * the block size. */
typedef uint32_t
(*compr_size_method_fn_t)(
    uint32_t            compr_size,
    const iobuf_opts_t *opts);

/* The compression method.  Caller must set '*destlen' to the
 * length of the destination buffer before calling.  */
typedef int
(*compr_method_fn_t)(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);

/* The decompression method.  Caller must set '*destlen' to the
 * length of the destination buffer before calling.  */
typedef int
(*uncompr_method_fn_t)(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);

/*
 *   The iobuf_methods_t structure defines the callback functions that
 *   need to be invoked for each type of compression.
 */
typedef struct iobuf_methods_st {
    init_method_fn_t        init_method;
    uninit_method_fn_t      uninit_method;
    compr_size_method_fn_t  compr_size_method;
    compr_method_fn_t       compr_method;
    uncompr_method_fn_t     uncompr_method;

    /* Whether this compression method expects the block sizes---that
     * is, a compr_sizes_t structure---before the compressed
     * blocks. */
    unsigned   block_numbers : 1;
} iobuf_methods_t;

/*
 *    In the 'methods' array below, the value for an iobuf_methods_t
 *    when the compression method is not available.
 */
#define SKIOBUF_METHOD_PLACEHOLDER  { NULL, NULL, NULL, NULL, NULL, 1 }

/*    Specify a iobuf_methods_t for each compression method. */

#if !SK_ENABLE_ZLIB
#define ZLIB_METHODS   SKIOBUF_METHOD_PLACEHOLDER
#else
#define ZLIB_METHODS                            \
    {                                           \
        zlib_init_method,                       \
        NULL,                                   \
        zlib_compr_size_method,                 \
        zlib_compr_method,                      \
        zlib_uncompr_method,                    \
        1                                       \
    }

/* Forward declarations for zlib methods */
static int
zlib_init_method(
    iobuf_opts_t       *opts);
static uint32_t
zlib_compr_size_method(
    uint32_t            compr_size,
    const iobuf_opts_t *opts);
static int
zlib_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
static int
zlib_uncompr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
#endif  /* SK_ENABLE_ZLIB */


#if !SK_ENABLE_LZO
#define LZO_METHODS   SKIOBUF_METHOD_PLACEHOLDER
#else
#define LZO_METHODS                             \
    {                                           \
        lzo_init_method,                        \
        lzo_uninit_method,                      \
        lzo_compr_size_method,                  \
        lzo_compr_method,                       \
        lzo_uncompr_method,                     \
        1                                       \
    }

/* Forward declarations for lzo methods */
static int
lzo_init_method(
    iobuf_opts_t       *opts);
static int
lzo_uninit_method(
    iobuf_opts_t       *opts);
static uint32_t
lzo_compr_size_method(
    uint32_t            compr_size,
    const iobuf_opts_t *opts);
static int
lzo_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
static int
lzo_uncompr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
#endif  /* SK_ENABLE_LZO */


#if !SK_ENABLE_SNAPPY
#define SNAPPY_METHODS   SKIOBUF_METHOD_PLACEHOLDER
#else
#define SNAPPY_METHODS                          \
    {                                           \
        NULL,                                   \
        NULL,                                   \
        snappy_compr_size_method,               \
        snappy_compr_method,                    \
        snappy_uncompr_method,                  \
        1                                       \
    }

/* Forward declarations for snappy methods */
static uint32_t
snappy_compr_size_method(
    uint32_t            compr_size,
    const iobuf_opts_t *opts);
static int
snappy_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
static int
snappy_uncompr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts);
#endif  /* SK_ENABLE_SNAPPY */


/*
 *    Variable to hold the methods for each type of compression that
 *    SiLK supports.
 */
static const iobuf_methods_t methods[] = {
    /* NONE */
    { NULL, NULL, NULL, NULL, NULL, 0 },
    ZLIB_METHODS,
    LZO_METHODS,
    SNAPPY_METHODS
};


/* FUNCTION DEFINITIONS */

/* Create an IO buffer */
sk_iobuf_t *
skIOBufCreate(
    skstream_mode_t     mode)
{
    sk_iobuf_t *fd;

    if (mode != SK_IO_READ && mode != SK_IO_WRITE && mode != SK_IO_APPEND) {
        skAbortBadCase(mode);
    }
    fd = (sk_iobuf_t*)calloc(1, sizeof(sk_iobuf_t));
    if (fd == NULL) {
        return NULL;
    }

    fd->block_size = fd->uncompr_buf_size = SKIOBUF_DEFAULT_BLOCKSIZE;
    fd->block_quantum = SKIOBUF_DEFAULT_RECORDSIZE;
    fd->compr_method = SK_COMPMETHOD_NONE;

    fd->is_writer = (SK_IO_READ != mode);

    return fd;
}


/* Destroy an IO buffer */
void
skIOBufDestroy(
    sk_iobuf_t         *fd)
{
    const iobuf_methods_t *method;

    if (NULL == fd) {
        return;
    }

    /* The flush call sets an error on a reader, but that's okay,
       since we are freeing the structure */
    skIOBufFlush(fd);
    if (fd->io.free_fd) {
        fd->io.free_fd(fd->fd);
    }

    if (fd->compr_buf) {
        free(fd->compr_buf);
    }
    if (fd->uncompr_buf) {
        free(fd->uncompr_buf);
    }
    method = &methods[fd->compr_method];
    if (method->uninit_method) {
        method->uninit_method(&fd->compr_opts);
    }

    free(fd);
}


/*
 *    Set the sizes of the compression buffer & decompression buffer
 *    on the IOBuf 'fd' based on the block_size, block_quantum, and
 *    the compression method.
 *
 *    Do not create the buffers.  If the buffers currently exist,
 *    delete them.
 */
static void
calculate_buffer_sizes(
    sk_iobuf_t         *fd)
{
    const iobuf_methods_t *method;

    method = &methods[fd->compr_method];

    fd->uncompr_buf_size = fd->block_size;
    fd->max_bytes = fd->block_size - (fd->block_size % fd->block_quantum);
    if (method->compr_size_method) {
        fd->compr_buf_size =
            method->compr_size_method(fd->block_size, &fd->compr_opts);
    } else {
        fd->compr_buf_size = fd->block_size;
    }

    if (fd->compr_buf) {
        free(fd->compr_buf);
        fd->compr_buf = NULL;
    }
    if (fd->uncompr_buf) {
        free(fd->uncompr_buf);
        fd->uncompr_buf = NULL;
    }

    if (!fd->is_writer) {
        fd->pos = fd->max_bytes;
    }
}


int
skIOBufBindAbstract(
    sk_iobuf_t         *fd,
    void               *caller_fd,
    sk_compmethod_t     compmethod,
    skio_abstract_t    *fd_ops)
{
    off_t total;
    const iobuf_methods_t *method;
    int rv = 0;

    if (NULL == fd) {
        return -1;
    }

    /* verify caller_fd and fd_ops */
    if (NULL == caller_fd) {
        return -1;
    }
    if (fd->is_writer) {
        if (NULL == fd_ops->write) {
            return -1;
        }
    } else if (NULL == fd_ops->read) {
        return -1;
    }

    /* verify compression method */
    switch (compmethod) {
      case SK_COMPMETHOD_NONE:
#if SK_ENABLE_ZLIB
      case SK_COMPMETHOD_ZLIB:
#endif
#if SK_ENABLE_LZO
      case SK_COMPMETHOD_LZO1X:
#endif
#if SK_ENABLE_SNAPPY
      case SK_COMPMETHOD_SNAPPY:
#endif
        break;

      default:
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BADCOMPMETHOD);
    }
    if (compmethod >= sizeof(methods)/sizeof(methods[0])) {
        skAbort();
    }

    /* This unbind code is probably completely wrong on the reading
     * side.  If the purpose is to be able to change the compression
     * method mid-stream, you do not want to throw away any data you
     * have pre-fetched using the old IO/compression methods. */

    /* flush the IO stream and free the current IO handler if needed */
    if (fd->fd_valid && fd->is_writer) {
        total = skIOBufFlush(fd);
        if (total == -1) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_INITFAIL);
        }
    }
    if (fd->io.free_fd) {
        fd->io.free_fd(fd->fd);
    }
    memset(&fd->io, 0, sizeof(fd->io));

    /* uninitialize the current compression method */
    method = &methods[fd->compr_method];
    if (method->uninit_method) {
        if (method->uninit_method(&fd->compr_opts)) {
            rv = -1;
        }
    }

    /* set the IO handler */
    fd->io = *fd_ops;
    fd->fd = caller_fd;
    fd->no_seek = (NULL == fd->io.seek);

    /* set the compression method */
    method = &methods[compmethod];

    fd->compr_method = compmethod;
    fd->total = 0;
    fd->used = 0;
    fd->has_error = 0;
    fd->has_interr = 0;
    fd->has_ioerr = 0;
    fd->io_errno = 0;
    fd->at_eof = 0;
    fd->is_uncompr = 0;

    /* Ensure the first read doesn't try to complete a skip */
    fd->in_core = 1;

    if (method->init_method) {
        if (method->init_method(&fd->compr_opts)) {
            return -1;
        }
    }

    calculate_buffer_sizes(fd);
    if (fd->uncompr_buf_size > SKIOBUF_MAX_BLOCKSIZE) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    fd->fd_valid = 1;

    return rv;
}


/* Handle actual read and decompression of a block */
static int32_t
skio_uncompr(
    sk_iobuf_t         *fd,
    skio_uncomp_t       mode)
{
    uint32_t comp_block_size, uncomp_block_size, new_block_size;
    /* to support buffer overruns when decompressing */
    uint32_t padded_uncomp_block_size;
    ssize_t readlen;
    uint8_t *bufpos;
    const iobuf_methods_t *method;

    assert(fd);

    /* assert that the mode is being used correctly */
    assert((mode == SKIO_UNCOMP_NORMAL) ||
           (mode == SKIO_UNCOMP_SKIP) ||
           (mode == SKIO_UNCOMP_REREAD && !fd->is_uncompr));

    /* Alias our methods. */
    method = &methods[fd->compr_method];

    /* When reading a new block, reset the block */
    if (mode != SKIO_UNCOMP_REREAD) {
        fd->in_core = 0;
        fd->is_uncompr = 0;
    }

    /* Determine our block sizes */
    if (mode == SKIO_UNCOMP_REREAD) {
        /* The sizes have already been read.  Get them from the fd */
        comp_block_size = fd->disk_block_size;
        uncomp_block_size = fd->max_bytes;
        new_block_size = fd->max_bytes;
        padded_uncomp_block_size = fd->max_bytes;
    } else if (!method->block_numbers) {
        /* Without block numbers, assume fd->max_bytes for
         * everything. */
        comp_block_size = fd->max_bytes;
        uncomp_block_size = fd->max_bytes;
        new_block_size = fd->max_bytes;
        padded_uncomp_block_size = fd->max_bytes;
    } else {
        /* Read in the compressed block sizes */
        readlen = fd->io.read(fd->fd, &comp_block_size,
                              sizeof(comp_block_size));
        if (readlen == -1) {
            SKIOBUF_IO_ERROR(fd);
        }
        if (readlen == 0) {
            /* We've reached eof. */
            fd->at_eof = 1;
            return 0;
        }
        fd->total += readlen;
        if ((size_t)readlen < sizeof(comp_block_size)) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_SHORTREAD);
        }

        /* If we have reached the end of the compressed stream, we
         * have the bytes we have. */
        if (comp_block_size == 0) {
            fd->at_eof = 1;
            return 0;
        }

        /* Read in the uncompressed block sizes */
        readlen = fd->io.read(fd->fd, &uncomp_block_size,
                              sizeof(uncomp_block_size));
        if (readlen == -1) {
            SKIOBUF_IO_ERROR(fd);
        }
        fd->total += readlen;
        if ((size_t)readlen < sizeof(uncomp_block_size)) {
            /* We've reached eof, though we weren't expecting to */
            fd->at_eof = 1;
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_SHORTREAD);
        }

        comp_block_size = ntohl(comp_block_size);
        uncomp_block_size = new_block_size = ntohl(uncomp_block_size);

        /*
         *   Some decompression algorithms require more space than the
         *   size of the decompressed data since they write data in
         *   4-byte chunks.  In particular, lzo1x_decompress_asm_fast
         *   has this requirement.  Account for that padding here.
         */
        padded_uncomp_block_size = 3 + uncomp_block_size;
    }

    /* Make sure block sizes aren't too large */
    if (comp_block_size > SKIOBUF_MAX_BLOCKSIZE ||
        padded_uncomp_block_size > SKIOBUF_MAX_BLOCKSIZE)
    {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    /* Save the size of the disk block size */
    fd->disk_block_size = comp_block_size;

    /* Reallocate buffers if necessary */
    if (method->uncompr_method != NULL &&
        (comp_block_size > fd->compr_buf_size ||
         fd->compr_buf == NULL))
    {
        assert(mode != SKIO_UNCOMP_REREAD);

        if (fd->compr_buf) {
            free(fd->compr_buf);
        }
        fd->compr_buf = (uint8_t*)malloc(comp_block_size);
        if (fd->compr_buf == NULL) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_MALLOC);
        }
        fd->compr_buf_size = comp_block_size;
    }
    if (padded_uncomp_block_size > fd->uncompr_buf_size ||
        fd->uncompr_buf == NULL)
    {
        assert(mode != SKIO_UNCOMP_REREAD);

        if (fd->uncompr_buf) {
            free(fd->uncompr_buf);
        }
        fd->uncompr_buf = (uint8_t*)malloc(padded_uncomp_block_size);
        if (fd->uncompr_buf == NULL) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_MALLOC);
        }
        fd->uncompr_buf_size = padded_uncomp_block_size;
    }

    /* Skip over data if we can */
    if (mode == SKIO_UNCOMP_SKIP && !fd->no_seek) {
        off_t end;
        off_t pos;

        errno = 0;

        /* Save current read position */
        fd->block_pos = fd->io.seek(fd->fd, 0, SEEK_CUR);
        if (fd->block_pos == (off_t)(-1)) {
            if (errno == ESPIPE) {
                fd->no_seek = 1;
                goto exit_skip;
            }
            SKIOBUF_IO_ERROR(fd);
        }
        /* Get EOF position */
        end = fd->io.seek(fd->fd, 0, SEEK_END);
        if (end == (off_t)(-1)) {
            SKIOBUF_IO_ERROR(fd);
        }
        /* Move to next block location */
        pos = fd->io.seek(fd->fd, fd->block_pos + comp_block_size,
                                    SEEK_SET);
        if (pos == (off_t)(-1)) {
            SKIOBUF_IO_ERROR(fd);
        }
        /* If next block is past EOF, read the last block */
        if (end < pos) {
            mode = SKIO_UNCOMP_REREAD;
            fd->pos = 0;
        }
    }
  exit_skip:

    /* If rereading, set our file position correctly. */
    if (mode == SKIO_UNCOMP_REREAD && !fd->in_core) {
        off_t pos;

        pos = fd->io.seek(fd->fd, fd->block_pos, SEEK_SET);
        if (pos == (off_t)(-1)) {
            SKIOBUF_IO_ERROR(fd);
        }
    }

    /* Read data when we must */
    if (mode == SKIO_UNCOMP_NORMAL ||
        (mode == SKIO_UNCOMP_REREAD && !fd->in_core) ||
        (mode == SKIO_UNCOMP_SKIP && fd->no_seek))
    {
        bufpos = method->uncompr_method ? fd->compr_buf : fd->uncompr_buf;
        readlen = fd->io.read(fd->fd, bufpos, comp_block_size);
        fd->in_core = 1;

        if (readlen == -1) {
            SKIOBUF_IO_ERROR(fd);
        }
        fd->total += readlen;
        if ((size_t)readlen < comp_block_size) {
            if (method->block_numbers) {
                SKIOBUF_INTERNAL_ERROR(fd, ESKIO_SHORTREAD);
            }
            fd->at_eof = 1;
            new_block_size = readlen;
            comp_block_size = readlen;
        }
    }

    /* Decompress it if we are not skipping it */
    if (mode != SKIO_UNCOMP_SKIP) {
        if (!method->uncompr_method) {
            /* If no decompression method, already uncompressed */
            fd->is_uncompr = 1;
        } else {
            /* Decompress */
            assert(fd->in_core);

            new_block_size = fd->uncompr_buf_size;
            if (method->uncompr_method(fd->uncompr_buf, &new_block_size,
                                       fd->compr_buf, comp_block_size,
                                       &fd->compr_opts))
            {
                SKIOBUF_INTERNAL_ERROR(fd, ESKIO_UNCOMP);
            }

            /* Verify the block's uncompressed size */
            if (new_block_size != uncomp_block_size) {
                SKIOBUF_INTERNAL_ERROR(fd, ESKIO_UNCOMP);
            }

            fd->is_uncompr = 1;
        }
    }

    /* Register the new data in the struct */
    fd->max_bytes = new_block_size;
    if (mode != SKIO_UNCOMP_REREAD) {
        /* Don't reset pos in an reread block */
        fd->pos = 0;
    }

    return new_block_size;
}


/* Read data from an IO buffer.  If 'c' is non-null, stop when the
 * char '*c' is encountered. */
static ssize_t
iobufRead(
    sk_iobuf_t         *fd,
    void               *buf,
    size_t              count,
    const int          *c)
{
    ssize_t       total   = 0;
    int           found_c = 0;
    skio_uncomp_t mode;

    assert(fd);

    /* Take care of boundary conditions */
    if (fd == NULL) {
        return -1;
    }
    if (fd->has_error) {
        return -1;
    }
    if (fd->is_writer) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOREAD);
    }
    if (!fd->fd_valid) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOFD);
    }
    if (count == 0) {
        return 0;
    }

    assert(count <= SSIZE_MAX);
    if (count > SSIZE_MAX) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_TOOBIG);
    }

    /* If we don't need the bytes, skip them */
    if (buf == NULL && c == NULL) {
        mode = SKIO_UNCOMP_SKIP;
    } else {
        mode = SKIO_UNCOMP_NORMAL;
    }

    /* Transfer the bytes */
    while (count && !found_c) {
        size_t   left = fd->max_bytes - fd->pos;
        size_t   num;
        void    *bufpos;

        /* If we have no bytes, we must get some. */
        if (left == 0) {
            int32_t uncompr_size;

            if (fd->at_eof) {
                break;
            }
            uncompr_size = skio_uncompr(fd, mode);
            if (uncompr_size == -1) {
                /* In an error condition, return those bytes we have
                 * successfully read.  A subsequent call to
                 * iobufRead() will return -1 because fd->has_error
                 * will be set. */
                return total ? total : -1;
            }
            fd->used = 1;
            left = fd->max_bytes;
            if (uncompr_size == 0) {
                assert(fd->at_eof);
                break;
            }

        } else if (!fd->is_uncompr && mode == SKIO_UNCOMP_NORMAL) {
            /* Read and/or uncompress real data, if needed. */
            int32_t rv = skio_uncompr(fd, SKIO_UNCOMP_REREAD);
            if (rv == -1) {
                return total ? total : -1;
            }
            if (rv == 0) {
                assert(fd->at_eof);
                break;
            }
        }

        /* Calculate how many bytes to read from our current buffer */
        num = (count < left) ? count : left;

        /* Copy the bytes, and update the data */
        bufpos = &fd->uncompr_buf[fd->pos];
        if (buf != NULL) {
            if (c != NULL) {
                void *after = memccpy(buf, bufpos, *c, num);
                if (after != NULL) {
                    found_c = 1;
                    num = ((uint8_t *)after) - ((uint8_t *)buf);
                }
            } else {
                memcpy(buf, bufpos, num);
            }
            buf = (uint8_t *)buf + num;
        } else if (c != NULL) {
            void *after = memchr(bufpos, *c, num);
            if (after != NULL) {
                found_c = 1;
                num = ((uint8_t *)after) - ((uint8_t *)bufpos) + 1;
            }
        }
        fd->pos += num;
        total += num;
        count -= num;
    }

    return total;
}


/* Standard read function for skiobuf */
ssize_t
skIOBufRead(
    sk_iobuf_t         *fd,
    void               *buf,
    size_t              count)
{
    return iobufRead(fd, buf, count, NULL);
}

/* Read until buffer full or character in 'c' encountered */
ssize_t
skIOBufReadToChar(
    sk_iobuf_t         *fd,
    void               *buf,
    size_t              count,
    int                 c)
{
    return iobufRead(fd, buf, count, &c);
}


/* Push 'count' bytes from 'buf' back into the read buffer.  */
ssize_t
skIOBufUnget(
    sk_iobuf_t         *fd,
    const void         *buf,
    size_t              count,
    off_t               adjust_total)
{
    /* Take care of boundary conditions */
    if (fd == NULL) {
        return -1;
    }
    if (fd->has_error) {
        return -1;
    }
    if (fd->is_writer) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOREAD);
    }
    if (!fd->fd_valid) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOFD);
    }

    if (0 == count) {
        fd->total += adjust_total;
        return 0;
    }
    if (NULL == buf) {
        return -1;
    }

    if (fd->pos < count) {
        /* not enough space is available */
        return fd->pos;
    }

    if (NULL == fd->uncompr_buf) {
        fd->uncompr_buf = (uint8_t*)malloc(fd->uncompr_buf_size);
        if (fd->uncompr_buf == NULL) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_MALLOC);
        }
        assert(fd->pos == fd->max_bytes);
        assert(fd->max_bytes <= fd->uncompr_buf_size);
    }

    /* move pos backward and insert 'buf' */
    fd->pos -= count;
    memcpy(&fd->uncompr_buf[fd->pos], buf, count);
    fd->total += adjust_total;
    return count;
}


/* Handle actual compression and write of a block */
static int32_t
skio_compr(
    sk_iobuf_t         *fd)
{
    uint32_t compr_size, uncompr_size;
    uint32_t size;
    ssize_t writelen;
    uint8_t *bufpos;
    const iobuf_methods_t *method;
    uint32_t extra;
    uint32_t offset;

    assert(fd);

    method = &methods[fd->compr_method];
    uncompr_size = fd->pos;

    extra = fd->pos % fd->block_quantum;
    /* Programmer's error if we don't have complete records */
    assert(extra == 0);
    /* If assertions aren't turned on, at least pad the record */
    if (extra != 0) {
        memset(&fd->uncompr_buf[fd->pos], 0, extra);
        uncompr_size += extra;
    }

    /* Extra bit added on for block sizes */
    offset = method->block_numbers ? sizeof(compr_sizes_t) : 0;

    /* Compress the block */
    if (method->compr_method) {

        /* Create the compression buffer, if necessary */
        if (fd->compr_buf == NULL) {
            fd->compr_buf = (uint8_t*)malloc(fd->compr_buf_size + offset);
            if (fd->compr_buf == NULL) {
                SKIOBUF_INTERNAL_ERROR(fd, ESKIO_MALLOC);
            }
        }

        compr_size = fd->compr_buf_size;
        if (method->compr_method(fd->compr_buf + offset, &compr_size,
                                 fd->uncompr_buf, uncompr_size,
                                 &fd->compr_opts) != 0)
        {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_COMP);
        }
        bufpos = fd->compr_buf;
    } else {
        compr_size = fd->pos;
        bufpos = fd->uncompr_buf;
    }

    size = compr_size + offset;

    if (method->block_numbers) {
        compr_sizes_t *sizes = (compr_sizes_t *)fd->compr_buf;

        /* Write out the block numbers */
        sizes->compr_size = htonl(compr_size);
        sizes->uncompr_size = htonl(uncompr_size);
    }

    /* Write out compressed data */
    writelen = fd->io.write(fd->fd, bufpos, size);
    if (writelen == -1) {
        SKIOBUF_IO_ERROR(fd);
    }
    fd->total += writelen;
    if ((size_t)writelen < size) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_SHORTWRITE);
    }

    fd->pos = 0;

    return (int32_t)writelen;
}


/* Write data to an IO buffer */
ssize_t
skIOBufWrite(
    sk_iobuf_t         *fd,
    const void         *buf,
    size_t              count)
{
    ssize_t total = 0;

    assert(fd);

    /* Take care of boundary conditions */
    if (count == 0) {
        return 0;
    }
    if (fd == NULL) {
        return -1;
    }
    if (!fd->is_writer) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOWRITE);
    }
    if (!fd->fd_valid) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOFD);
    }
    assert(count <= SSIZE_MAX);
    if (count > SSIZE_MAX) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_TOOBIG);
    }

    fd->used = 1;

    /* If the buffer hasn't been created yet, create it. */
    if (fd->uncompr_buf == NULL) {
        fd->uncompr_buf = (uint8_t*)malloc(fd->uncompr_buf_size);
        if (fd->uncompr_buf == NULL) {
            SKIOBUF_INTERNAL_ERROR(fd, ESKIO_MALLOC);
        }
    }

    /* Transfer the bytes */
    while (count) {
        size_t left = fd->max_bytes - fd->pos;
        size_t num;

        /* If we have filled the buffer, we must write it out. */
        if (left == 0) {
            int32_t compr_size = skio_compr(fd);

            if (compr_size == -1) {
                return -1;
            }

            left = fd->max_bytes;
        }

        /* Calculate how many bytes to write into our current buffer */
        num = (count < left) ? count : left;

        /* Copy the bytes, and update the data */
        memcpy(&fd->uncompr_buf[fd->pos], buf, num);
        fd->pos += num;
        total += num;
        count -= num;
        buf = (uint8_t *)buf + num;
    }

    return total;
}


/* Finish writing to an IO buffer */
off_t
skIOBufFlush(
    sk_iobuf_t         *fd)
{
    assert(fd);
    if (fd == NULL) {
        return -1;
    }
    if (!fd->is_writer) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOWRITE);
    }
    if (!fd->fd_valid) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOFD);
    }

    if (fd->pos) {
        int32_t compr_size = skio_compr(fd);
        if (compr_size == -1) {
            return -1;
        }
    }

    if (fd->io.flush) {
        fd->io.flush(fd->fd);
    }

    return fd->total;
}


/* Total number of bytes read/written from/to file descriptor */
off_t
skIOBufTotal(
    sk_iobuf_t         *fd)
{
    assert(fd);
    if (fd == NULL) {
        return -1;
    }

    return fd->total;
}


/* Maximum total number of bytes in a compressed block */
uint32_t
skIOBufUpperCompBlockSize(
    sk_iobuf_t         *fd)
{
    const iobuf_methods_t *method;
    uint32_t total;

    assert(fd);
    assert(fd->is_writer);

    method = &methods[fd->compr_method];

    if (method->compr_size_method) {
        total = method->compr_size_method(fd->max_bytes, &fd->compr_opts);
    } else {
        total = fd->max_bytes;
    }

    if (method->block_numbers) {
        total += sizeof(compr_sizes_t);
    }

    return total;
}


/* Maximum total number of bytes written to file descriptor after a flush */
off_t
skIOBufTotalUpperBound(
    sk_iobuf_t         *fd)
{
    const iobuf_methods_t *method;
    off_t total;

    assert(fd);
    if (fd == NULL) {
        return -1;
    }
    if (!fd->is_writer) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_NOWRITE);
    }

    method = &methods[fd->compr_method];

    total = fd->total + fd->pos;
    if (method->block_numbers) {
        total += sizeof(compr_sizes_t);
    }
    if (method->compr_size_method) {
        total += (method->compr_size_method(fd->max_bytes, &fd->compr_opts)
                  - fd->max_bytes);
    }

    return total;
}


/* Sets the block size */
int
skIOBufSetBlockSize(
    sk_iobuf_t         *fd,
    uint32_t            size)
{
    assert(fd);
    if (fd == NULL) {
        return -1;
    }
    if (fd->used) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_USED);
    }
    if (size > SKIOBUF_MAX_BLOCKSIZE) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }
    if (size < fd->block_quantum) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    fd->block_size = size;
    calculate_buffer_sizes(fd);
    if (fd->uncompr_buf_size > SKIOBUF_MAX_BLOCKSIZE) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    return 0;
}


/* Sets the write quantum */
int
skIOBufSetRecordSize(
    sk_iobuf_t         *fd,
    uint32_t            size)
{
    assert(fd);
    if (fd == NULL) {
        return -1;
    }
    if (fd->used) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_USED);
    }
    if (size > fd->block_size) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    fd->block_quantum = size;
    calculate_buffer_sizes(fd);
    if (fd->uncompr_buf_size > SKIOBUF_MAX_BLOCKSIZE) {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BLOCKSIZE);
    }

    return 0;
}


/* Create an error message */
const char *
skIOBufStrError(
    sk_iobuf_t         *fd)
{
    static char buf[256];
    static const char *message;

    message = buf;
    if (!fd->has_error) {
        message = "No error";
    } else if (fd->has_interr) {
        snprintf(buf, sizeof(buf), "%s",
                 internal_messages[fd->io_errno]);
    } else if (fd->has_ioerr && fd->io.strerror) {
        snprintf(buf, sizeof(buf), "%s",
                 fd->io.strerror(fd->fd, fd->io_errno));
    } else {
        snprintf(buf, sizeof(buf), "%s",
                 strerror(fd->io_errno));
    }

    fd->has_error = 0;
    fd->has_interr = 0;
    fd->has_ioerr = 0;
    fd->io_errno = 0;

    return message;
}


/*  SIMPLE READ/WRITE methods */


/* skio_abstract_t.read; Wrapper around simple read */
static ssize_t
raw_read(
    void               *vfd,
    void               *dest,
    size_t              count)
{
    int *fd = (int *)vfd;
    return skreadn(*fd, dest, count);
}


/* skio_abstract_t.write; Wrapper around simple write */
static ssize_t
raw_write(
    void               *vfd,
    const void         *src,
    size_t              count)
{
    int *fd = (int *)vfd;
    return skwriten(*fd, src, count);
}


/* skio_abstract_t.seek; Wrapper around simple lseek */
static off_t
raw_seek(
    void               *vfd,
    off_t               offset,
    int                 whence)
{
    int *fd = (int *)vfd;
    return lseek(*fd, offset, whence);
}


/* skio_abstract_t.strerror; Wrapper around simple strerror */
static const char *
raw_strerror(
    void        UNUSED(*vfd),
    int                 io_errno)
{
    return strerror(io_errno);
}


/* Bind an IO buffer */
int
skIOBufBind(
    sk_iobuf_t         *fd,
    int                 file,
    sk_compmethod_t     compmethod)
{
    skio_abstract_t io;
    int *fh;
    int rv;

    fh = (int*)malloc(sizeof(*fh));
    if (fh == NULL) {
        return -1;
    }
    *fh = file;
    io.read = &raw_read;
    io.write = &raw_write;
    io.seek = &raw_seek;
    io.strerror = &raw_strerror;
    io.flush = NULL;
    io.free_fd = &free;
    rv = skIOBufBindAbstract(fd, fh, compmethod, &io);
    if (0 != rv) {
        free(fh);
    }
    return rv;
}


#if SK_ENABLE_ZLIB

/* ZLIB methods */

/* iobuf_methods_t.init_method */
static int
zlib_init_method(
    iobuf_opts_t       *opts)
{
    opts->zlib.level = Z_DEFAULT_COMPRESSION;
    return 0;
}


/* iobuf_methods_t.compr_size_method */
static uint32_t
zlib_compr_size_method(
    uint32_t                    compr_size,
    const iobuf_opts_t  UNUSED(*opts))
{
#ifdef SK_HAVE_COMPRESSBOUND
    return compressBound(compr_size);
#else
    return compr_size + compr_size / 1000 + 12;
#endif
}


/* iobuf_methods_t.compr_method */
static int
zlib_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts)
{
    uLongf dl;
    uLong  sl;
    int    rv;

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    sl = sourcelen;
    dl = *destlen;
    rv = compress2((Bytef*)dest, &dl, (const Bytef*)source, sl,
                   opts->zlib.level);
    *destlen = dl;

    rv = (rv == Z_OK) ? 0 : -1;

    return rv;
}


/* iobuf_methods_t.uncompr_method */
static int
zlib_uncompr_method(
    void                       *dest,
    uint32_t                   *destlen,
    const void                 *source,
    uint32_t                    sourcelen,
    const iobuf_opts_t  UNUSED(*opts))
{
    uLongf dl;
    uLong  sl;
    int    rv;

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    sl = sourcelen;
    dl = *destlen;
    rv = uncompress((Bytef*)dest, &dl, (Bytef*)source, sl);
    *destlen = dl;

    rv = (rv == Z_OK) ? 0 : -1;

    return rv;
}


#if 0
/* skio_abstract_t.strerror */
static const char *
gz_strerror(
    void               *vfd,
    int                 io_errno)
{
    int gzerr;
    gzFile fd = (gzFile)vfd;
    const char *errstr;

    errstr =  gzerror(fd, &gzerr);
    if (gzerr == Z_ERRNO) {
        errstr = strerror(io_errno);
    }
    return errstr;
}


/* skio_abstract_t.flush */
static int
gz_flush(
    void               *vfd)
{
    gzFile fd = (gzFile)vfd;
    return gzflush(fd, Z_SYNC_FLUSH);
}


/**
 *    Binds the gzip file descriptor 'fd' to the IO buffer.  If the IO
 *    buffer is a writer and is already associated with a file
 *    descriptor, the buffer will be flushed before binding.  Binding
 *    a file descriptor resets the write/read count of the IO buffer.
 *    'compmethod' is a valid compression method from silk_files.h.
 *
 *    Returns 0 on success, -1 on failure.
 */
int
skIOBufBindGzip(
    sk_iobuf_t         *fd,
    gzFile              file,
    sk_compmethod_t     compmethod)
{
    skio_abstract_t io;

    io.read = (skio_read_fn_t)&gzread;
    io.write = (skio_write_fn_t)&gzwrite;
    io.seek = NULL;
    io.strerror = &gz_strerror;
    io.flush = &gz_flush;
    io.free_fd = NULL;
    return skIOBufBindAbstract(fd, file, compmethod, &io);
}


/**
 *    Sets the compression level for zlib-based IO buffers.  Returns 0
 *    on success, -1 on error.
 */
int
skIOBufSetZlibLevel(
    sk_iobuf_t         *fd,
    int                 level)
{
    assert(fd);
    if (fd == NULL) {
        return -1;
    }

    if (!(level >= Z_BEST_SPEED && level <= Z_BEST_COMPRESSION) &&
        level != Z_NO_COMPRESSION && level != Z_DEFAULT_COMPRESSION)
    {
        SKIOBUF_INTERNAL_ERROR(fd, ESKIO_BADOPT);
    }

    fd->compr_opts.zlib.level = level;

    return 0;
}
#endif  /* 0 */
#endif  /* SK_ENABLE_ZLIB */


#if SK_ENABLE_LZO

/* LZO methods */

/* iobuf_methods_t.init_method */
static int
lzo_init_method(
    iobuf_opts_t       *opts)
{
    static int initialized = 0;

    if (initialized) {
        if (lzo_init()) {
            return -1;
        }
        initialized = 1;
    }

    opts->lzo.scratch = (uint8_t *)calloc(LZO1X_1_15_MEM_COMPRESS, 1);
    if (opts->lzo.scratch == NULL) {
        return -1;
    }

    return 0;
}


/* iobuf_methods_t.uninit_method */
static int
lzo_uninit_method(
    iobuf_opts_t       *opts)
{
    assert(opts->lzo.scratch != NULL);
    free(opts->lzo.scratch);
    opts->lzo.scratch = NULL;
    return 0;
}


/* iobuf_methods_t.compr_size_method */
static uint32_t
lzo_compr_size_method(
    uint32_t                    compr_size,
    const iobuf_opts_t  UNUSED(*opts))
{
    /* The following formula is in the lzo faq:
       http://www.oberhumer.com/opensource/lzo/lzofaq.php */
    return (compr_size + (compr_size >> 4) + 64 + 3);
}


/* iobuf_methods_t.compr_method */
static int
lzo_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts)
{
    lzo_uint sl, dl;
    int rv;

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    dl = *destlen;
    sl = sourcelen;
    rv = lzo1x_1_15_compress((const unsigned char*)source, sl,
                             (unsigned char*)dest, &dl, opts->lzo.scratch);
    *destlen = dl;

    return rv;
}


/* iobuf_methods_t.uncompr_method */
static int
lzo_uncompr_method(
    void                       *dest,
    uint32_t                   *destlen,
    const void                 *source,
    uint32_t                    sourcelen,
    const iobuf_opts_t  UNUSED(*opts))
{
    lzo_uint sl, dl;
    int rv;

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    dl = *destlen;
    sl = sourcelen;
#ifdef SK_HAVE_LZO1X_DECOMPRESS_ASM_FAST_SAFE
    rv = lzo1x_decompress_asm_fast_safe(source, sl, dest, &dl, NULL);
#else
    rv = lzo1x_decompress_safe((const unsigned char*)source, sl,
                               (unsigned char*)dest, &dl, NULL);
#endif
    *destlen = dl;

    return rv;
}

#endif  /* SK_ENABLE_LZO */


#if SK_ENABLE_SNAPPY

/* SNAPPY methods */

/* iobuf_methods_t.init_method */

/* iobuf_methods_t.uninit_method */

/* iobuf_methods_t.compr_size_method */
static uint32_t
snappy_compr_size_method(
    uint32_t            compr_size,
    const iobuf_opts_t *opts)
{
    (void)opts;                 /* UNUSED */

    return (uint32_t)snappy_max_compressed_length(compr_size);
}


/* iobuf_methods_t.compr_method */
static int
snappy_compr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts)
{
    size_t sl, dl;
    snappy_status rv;

    (void)opts;                 /* UNUSED */

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    dl = *destlen;
    sl = sourcelen;
    rv = snappy_compress((const char*)source, sl, (char*)dest, &dl);
    *destlen = dl;

    return rv;
}


/* iobuf_methods_t.uncompr_method */
static int
snappy_uncompr_method(
    void               *dest,
    uint32_t           *destlen,
    const void         *source,
    uint32_t            sourcelen,
    const iobuf_opts_t *opts)
{
    size_t sl, dl;
    snappy_status rv;

    (void)opts;                 /* UNUSED */

    assert(sizeof(sl) >= sizeof(sourcelen));
    assert(sizeof(dl) >= sizeof(*destlen));

    dl = *destlen;
    sl = sourcelen;
    rv = snappy_uncompress((const char*)source, sl, (char*)dest, &dl);
    *destlen = dl;

    return rv;
}

#endif  /* SK_ENABLE_SNAPPY */


/*
** Local Variables:
** mode:c
** indent-tabs-mode:nil
** c-basic-offset:4
** End:
*/
